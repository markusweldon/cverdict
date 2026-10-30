/**
 * Git plumbing for reading large repositories without a checkout: streaming `ls-tree`, a single
 * long-lived `cat-file --batch` process, and management of shallow, checkout-free cache clones.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdir, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import type { Writable } from 'node:stream';
import type { Logger } from '../types';

export class GitError extends Error {
  override name = 'GitError';
}

export interface GitRunOptions {
  /** Repository (or, for clone, parent) directory. */
  cwd?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

interface Exit {
  code: number | null;
  signal: NodeJS.Signals | null;
  error: Error | null;
}

const STDERR_LIMIT = 4096;

function gitEnv(cwd: string | undefined): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GIT_TERMINAL_PROMPT: '0',
    LC_ALL: 'C',
    // Never let git walk up from `cwd` into an enclosing repository (e.g. this project's own
    // checkout when the cache directory lives inside it).
    ...(cwd ? { GIT_CEILING_DIRECTORIES: path.dirname(path.resolve(cwd)) } : {}),
  };
}

function spawnGit(args: readonly string[], opts: GitRunOptions, stdin: 'pipe' | 'ignore'): ChildProcess {
  return spawn('git', args, {
    cwd: opts.cwd,
    env: gitEnv(opts.cwd),
    stdio: [stdin, 'pipe', 'pipe'],
    timeout: opts.timeoutMs,
    signal: opts.signal,
  });
}

/** Resolves (never rejects) once the process has exited and its streams are closed. */
function exitOf(proc: ChildProcess): Promise<Exit> {
  return new Promise((resolve) => {
    let error: Error | null = null;
    proc.on('error', (err) => {
      error = err;
      // A process that failed to spawn never emits 'close'.
      if (proc.pid === undefined) resolve({ code: null, signal: null, error });
    });
    proc.once('close', (code, signal) => resolve({ code, signal, error }));
  });
}

function collectStderr(proc: ChildProcess): () => string {
  let tail = '';
  proc.stderr?.setEncoding('utf8');
  proc.stderr?.on('data', (s: string) => {
    tail = (tail + s).slice(-STDERR_LIMIT);
  });
  return () => tail.trim();
}

function failure(args: readonly string[], exit: Exit, stderr: string): GitError {
  const why = exit.error?.message ?? (exit.signal ? `killed by ${exit.signal}` : `exit code ${exit.code}`);
  return new GitError(`git ${args.join(' ')} failed (${why})${stderr ? `: ${stderr}` : ''}`);
}

/** Run git to completion and return its trimmed stdout. For commands with small output. */
export async function git(args: readonly string[], opts: GitRunOptions = {}): Promise<string> {
  const proc = spawnGit(args, opts, 'ignore');
  const stderr = collectStderr(proc);
  const out: Buffer[] = [];
  proc.stdout?.on('data', (chunk: Buffer) => out.push(chunk));
  const exit = await exitOf(proc);
  if (exit.error || exit.code !== 0) throw failure(args, exit, stderr());
  return Buffer.concat(out).toString('utf8').trim();
}

export interface TreeEntry {
  mode: string;
  /** "blob", "tree" or "commit" (submodule). */
  type: string;
  sha: string;
  path: string;
}

function parseTreeEntry(record: string): TreeEntry {
  // <mode> SP <type> SP <object> TAB <path>
  const tab = record.indexOf('\t');
  const [mode, type, sha] = record.slice(0, tab).split(' ');
  if (tab === -1 || !sha) throw new GitError(`unexpected ls-tree output: ${record.slice(0, 200)}`);
  return { mode, type, sha, path: record.slice(tab + 1) };
}

/** Stream `git ls-tree -r -z <rev> -- <paths>` without buffering the listing. */
export async function* lsTree(
  repoDir: string,
  rev: string,
  paths: readonly string[] = [],
  signal?: AbortSignal,
): AsyncGenerator<TreeEntry> {
  const args = ['ls-tree', '-r', '-z', rev, '--', ...paths];
  const proc = spawnGit(args, { cwd: repoDir, signal }, 'ignore');
  const exited = exitOf(proc);
  const stderr = collectStderr(proc);
  const decoder = new StringDecoder('utf8');
  let rest = '';
  let complete = false;
  try {
    for await (const chunk of proc.stdout as AsyncIterable<Buffer>) {
      const text = rest + decoder.write(chunk);
      let start = 0;
      for (let end = text.indexOf('\0'); end !== -1; end = text.indexOf('\0', start)) {
        yield parseTreeEntry(text.slice(start, end));
        start = end + 1;
      }
      rest = text.slice(start);
    }
    complete = true;
  } finally {
    if (!complete) proc.kill();
  }
  const exit = await exited;
  if (exit.error || exit.code !== 0) throw failure(args, exit, stderr());
  if (rest + decoder.end() !== '') throw new GitError('git ls-tree output ended mid-entry');
}

/** FIFO with O(1) shift, for requests awaiting their cat-file response. */
class Fifo<T> {
  private items: (T | undefined)[] = [];
  private head = 0;

  get size(): number {
    return this.items.length - this.head;
  }

  push(item: T): void {
    this.items.push(item);
  }

  shift(): T | undefined {
    if (this.head >= this.items.length) return undefined;
    const item = this.items[this.head];
    this.items[this.head++] = undefined;
    if (this.head >= 4096 && this.head * 2 >= this.items.length) {
      this.items = this.items.slice(this.head);
      this.head = 0;
    }
    return item;
  }
}

interface BatchObject {
  name: string;
  /** Object type, or "missing" / "ambiguous" when git could not resolve the request. */
  type: string;
  data: Buffer | null;
}

/** Incremental parser for `git cat-file --batch` output: `<sha> <type> <size>\n<bytes>\n`. */
export class BatchOutputParser {
  private chunks: Buffer[] = [];
  private buffered = 0;
  private header: { name: string; type: string; size: number } | null = null;

  /** True when no partial object is buffered. */
  get idle(): boolean {
    return this.header === null && this.buffered === 0;
  }

  /** Feed a chunk of stdout; returns the objects it completed, in order. */
  push(chunk: Buffer): BatchObject[] {
    this.chunks.push(chunk);
    this.buffered += chunk.length;
    const out: BatchObject[] = [];
    for (;;) {
      if (this.header === null) {
        const line = this.readLine();
        if (line === null) break;
        const parts = line.split(' ');
        if (parts.length === 2 && (parts[1] === 'missing' || parts[1] === 'ambiguous')) {
          out.push({ name: parts[0], type: parts[1], data: null });
          continue;
        }
        const size = Number(parts[2]);
        if (parts.length !== 3 || !Number.isSafeInteger(size) || size < 0) {
          throw new GitError(`unexpected cat-file header: ${line.slice(0, 200)}`);
        }
        this.header = { name: parts[0], type: parts[1], size };
      }
      // Body plus the trailing LF.
      if (this.buffered < this.header.size + 1) break;
      const body = this.take(this.header.size + 1);
      out.push({ name: this.header.name, type: this.header.type, data: body.subarray(0, this.header.size) });
      this.header = null;
    }
    return out;
  }

  private readLine(): string | null {
    let offset = 0;
    for (const chunk of this.chunks) {
      const nl = chunk.indexOf(0x0a);
      if (nl !== -1) {
        const line = this.take(offset + nl + 1);
        return line.toString('latin1', 0, line.length - 1);
      }
      offset += chunk.length;
    }
    return null;
  }

  /** Remove and return the first `n` buffered bytes, copying only when they span chunks. */
  private take(n: number): Buffer {
    this.buffered -= n;
    const first = this.chunks[0];
    if (first.length >= n) {
      if (first.length === n) this.chunks.shift();
      else this.chunks[0] = first.subarray(n);
      return first.subarray(0, n);
    }
    const parts: Buffer[] = [];
    let need = n;
    while (need > 0) {
      const chunk = this.chunks[0];
      if (chunk.length <= need) {
        parts.push(chunk);
        this.chunks.shift();
        need -= chunk.length;
      } else {
        parts.push(chunk.subarray(0, need));
        this.chunks[0] = chunk.subarray(need);
        need = 0;
      }
    }
    return Buffer.concat(parts, n);
  }
}

function drained(stream: Writable): Promise<void> {
  return new Promise((resolve) => {
    if (stream.destroyed) return resolve();
    const done = () => {
      stream.off('drain', done);
      stream.off('close', done);
      resolve();
    };
    stream.once('drain', done);
    stream.once('close', done);
  });
}

/** Feed object names to cat-file's stdin with backpressure. Resolves with the error, if any. */
async function writeRequests<T>(
  stdin: Writable,
  items: AsyncIterable<T> | Iterable<T>,
  nameOf: (item: T) => string,
  pending: Fifo<T>,
): Promise<Error | null> {
  try {
    for await (const item of items) {
      if (stdin.destroyed) break;
      pending.push(item);
      if (!stdin.write(`${nameOf(item)}\n`)) await drained(stdin);
    }
    return null;
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  } finally {
    stdin.end();
  }
}

export interface BatchResult<T> {
  item: T;
  /** Object contents, or null when the object does not exist. */
  data: Buffer | null;
}

/**
 * Read many objects through ONE `git cat-file --batch` process, pipelining requests with
 * backpressure. `items` may be lazy (e.g. an lsTree stream), so memory stays bounded by the
 * pipe buffers. Results come back in request order. Breaking out of the loop stops git.
 */
export async function* catFileBatch<T>(
  repoDir: string,
  items: AsyncIterable<T> | Iterable<T>,
  nameOf: (item: T) => string,
  signal?: AbortSignal,
): AsyncGenerator<BatchResult<T>> {
  const args = ['cat-file', '--batch', '--buffer'];
  const proc = spawnGit(args, { cwd: repoDir, signal }, 'pipe');
  const stdin = proc.stdin as Writable;
  const exited = exitOf(proc);
  const stderr = collectStderr(proc);
  // EPIPE when git dies early is reported through the exit status instead.
  stdin.on('error', () => {});
  const pending = new Fifo<T>();
  const writer = writeRequests(stdin, items, nameOf, pending);
  const parser = new BatchOutputParser();
  let complete = false;
  try {
    for await (const chunk of proc.stdout as AsyncIterable<Buffer>) {
      for (const obj of parser.push(chunk)) {
        if (pending.size === 0) throw new GitError(`git cat-file returned an unrequested object ${obj.name}`);
        yield { item: pending.shift() as T, data: obj.data };
      }
    }
    complete = true;
  } finally {
    if (!complete) {
      stdin.destroy();
      proc.kill();
      await writer;
    }
  }
  const writeError = await writer;
  const exit = await exited;
  if (writeError) throw writeError;
  if (exit.error || exit.code !== 0) throw failure(args, exit, stderr());
  if (pending.size > 0 || !parser.idle) throw new GitError('git cat-file output ended early');
}

/** Full commit SHA that `rev` resolves to in `repoDir`. */
export function resolveCommit(repoDir: string, rev: string, signal?: AbortSignal): Promise<string> {
  return git(['rev-parse', '--verify', '--quiet', `${rev}^{commit}`], { cwd: repoDir, signal });
}

/** Committer date of `commit` as ISO 8601. */
export async function commitDate(repoDir: string, commit: string, signal?: AbortSignal): Promise<string | null> {
  const out = await git(['show', '-s', '--format=%cI', commit], { cwd: repoDir, signal });
  const ms = Date.parse(out);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

async function headOf(dir: string): Promise<string | null> {
  try {
    if (!(await stat(dir)).isDirectory()) return null;
    return await resolveCommit(dir, 'HEAD');
  } catch {
    return null;
  }
}

/** HEAD commit of an existing repository given by the user (read-only use). */
export async function existingRepoHead(dir: string, signal?: AbortSignal): Promise<string> {
  const isDir = await stat(dir).then((s) => s.isDirectory(), () => false);
  if (!isDir) throw new GitError(`${dir} is not a directory`);
  return resolveCommit(dir, 'HEAD', signal);
}

export interface CloneSpec {
  remote: string;
  branch: string;
  /** Clone location; created if missing. */
  dir: string;
  offline: boolean;
  log: Logger;
  timeoutMs: number;
  signal?: AbortSignal;
  /**
   * Sanity check for a newly fetched commit (in `repoDir`). Return an error message to reject
   * it; the previously adopted commit is then kept.
   */
  accept: (repoDir: string, commit: string) => Promise<string | null>;
}

export interface SyncedClone {
  dir: string;
  commit: string;
  /** True when the newest upstream commit could not be fetched or was rejected. */
  stale: boolean;
  error: string | null;
}

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err));

/**
 * Bring a shallow, checkout-free cache clone up to date: clone it if missing, otherwise
 * `git fetch --depth 1 origin <branch>` and adopt FETCH_HEAD. A new commit is adopted (HEAD
 * moved) only after `accept` passes, so a bad upstream state never replaces the last good one.
 * Throws only when there is no usable commit at all.
 */
export async function syncShallowClone(spec: CloneSpec): Promise<SyncedClone> {
  const { dir, log, signal } = spec;
  const name = path.basename(dir);
  const current = await headOf(dir);
  if (spec.offline) {
    if (!current) throw new GitError(`offline and no usable clone at ${dir}`);
    return { dir, commit: current, stale: true, error: null };
  }

  let candidate: { dir: string; commit: string };
  const started = performance.now();
  try {
    if (current) {
      await git(['fetch', '--depth', '1', '--no-tags', 'origin', spec.branch], { cwd: dir, timeoutMs: spec.timeoutMs, signal });
      candidate = { dir, commit: await resolveCommit(dir, 'FETCH_HEAD', signal) };
    } else {
      candidate = await cloneFresh(spec);
    }
  } catch (err) {
    if (!current) throw err;
    log.warn(`${name}: fetch failed, using the cached clone (${errorText(err)})`);
    return { dir, commit: current, stale: true, error: errorText(err) };
  }
  log.info(`${name}: ${current ? 'fetched' : 'cloned'} ${candidate.commit.slice(0, 12)} in ${((performance.now() - started) / 1000).toFixed(1)}s`);
  if (candidate.commit === current) return { dir, commit: current, stale: false, error: null };

  const problem = await spec.accept(candidate.dir, candidate.commit);
  if (problem) {
    if (!current) {
      await rm(candidate.dir, { recursive: true, force: true });
      throw new GitError(`${name}: ${problem}`);
    }
    log.warn(`${name}: rejected ${candidate.commit.slice(0, 12)} (${problem}); keeping ${current.slice(0, 12)}`);
    return { dir, commit: current, stale: true, error: problem };
  }
  if (current) {
    await git(['update-ref', 'HEAD', candidate.commit], { cwd: dir, signal });
  } else {
    await rm(dir, { recursive: true, force: true });
    await rename(candidate.dir, dir);
  }
  return { dir, commit: candidate.commit, stale: false, error: null };
}

/** Clone into a temporary sibling directory so a half-finished clone never looks usable. */
async function cloneFresh(spec: CloneSpec): Promise<{ dir: string; commit: string }> {
  // Absolute, because git runs with the parent as cwd and would resolve a relative target twice.
  const tmp = path.resolve(`${spec.dir}.tmp-${process.pid}`);
  await rm(tmp, { recursive: true, force: true });
  await mkdir(path.dirname(spec.dir), { recursive: true });
  try {
    await git(
      ['clone', '--depth', '1', '--no-checkout', '--single-branch', '--no-tags', '--branch', spec.branch, spec.remote, tmp],
      { cwd: path.dirname(spec.dir), timeoutMs: spec.timeoutMs, signal: spec.signal },
    );
    return { dir: tmp, commit: await resolveCommit(tmp, 'HEAD', spec.signal) };
  } catch (err) {
    await rm(tmp, { recursive: true, force: true });
    throw err;
  }
}
