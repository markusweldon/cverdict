/**
 * When the first Nuclei template for each CVE landed on the main branch of
 * projectdiscovery/nuclei-templates, read from the repository's own history.
 *
 * The landing day of a commit is the committer date of the commit on main's first-parent chain
 * that brought it in: for a merged pull request that is the merge (or squash) commit, not the
 * branch commit that authored the template. Each first-parent commit is diffed against its first
 * parent with rename detection off, so a move (cves/ → http/cves/) shows as an addition at the new
 * path; deletions are ignored, and every CVE keeps the earliest landing across all its paths
 * (so a template deleted and added again keeps its first date). Committer dates along the chain
 * are clamped to never go backwards and never past the time of the walk: a commit cannot land
 * before the commits it builds on, nor after we saw it.
 *
 * Cost: the clone is blobless (commits and trees only, no file contents). A cold clone and full
 * walk took about 15 s and 159 MB on 2026-11-13. The dates (CVE → landing time and commit) are
 * kept in `<cache>/sources/nuclei-dates.json`, which the hourly workflow caches with the other
 * downloads; a run that has it makes a shallow clone (about 35 MB, 5 s) and walks only the commits
 * since the last one walked. On any failure the previous dates are kept and the source is marked stale.
 */
import { mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { NUCLEI, type SanityLimits } from '../config';
import type { Logger } from '../types';
import { git, GitError } from '../util/git';
import { since } from '../util/log';
import { normalizeCveId } from '../util/text';

/** When a CVE's first template landed on main, and the first-parent commit that landed it. */
export interface NucleiAdded {
  /** ISO 8601 UTC. */
  at: string;
  commit: string;
}

export interface NucleiDatesResult {
  /** CVE ID → first landing; null when no dates could be built or read. */
  dates: Map<string, NucleiAdded> | null;
  /** Last commit of main that the dates include. */
  head: string | null;
  /** True when the dates may miss the newest commits (fetch failed, offline, a cached copy). */
  stale: boolean;
  error: string | null;
}

/** The cached dates file. */
export interface NucleiDatesFile {
  version: 1;
  remote: string;
  branch: string;
  /** Last first-parent commit walked. */
  head: string;
  /** Its committer date (ISO). */
  head_at: string;
  /** Its clamped landing time (ISO): the floor for the next commits. */
  landed: string;
  updated_at: string;
  /** CVE ID → [landing ISO, commit SHA]. */
  dates: Record<string, [string, string]>;
}

const SHA_RE = /^[0-9a-f]{40}$/;
// A CVE ID anywhere in the file name, not inside a longer token ("spring4shell-CVE-2022-22965.yaml").
const CVE_TOKEN_RE = /(?<![a-z0-9])cve-(\d{4})-(\d{4,})(?!\d)/gi;
// Folders that hold workflows, helpers and payloads, never a template for the CVE in the name.
const NOT_TEMPLATES = new Set(['.github', 'helpers', 'payloads', 'workflows', 'profiles']);

/**
 * The CVE a template path is for: a `.yaml`/`.yml` file whose name holds exactly one CVE ID, in
 * any case and folder (`cves/2021/…`, `http/cves/2021/…`, `network/cves/…`). Null otherwise.
 */
export function cveFromTemplatePath(file: string): string | null {
  if (!/\.ya?ml$/i.test(file)) return null;
  const parts = file.split('/');
  if (parts.slice(0, -1).some((p) => NOT_TEMPLATES.has(p.toLowerCase()))) return null;
  const ids = new Set<string>();
  for (const m of parts[parts.length - 1].matchAll(CVE_TOKEN_RE)) {
    const id = normalizeCveId(`CVE-${m[1]}-${m[2]}`);
    if (id) ids.add(id);
  }
  return ids.size === 1 ? [...ids][0] : null;
}

export interface FirstParentCommit {
  sha: string;
  /** Committer time, epoch seconds. */
  ct: number;
  /** First parent, or null for a root (or shallow boundary) commit. */
  parent: string | null;
}

/** Parse `git log --first-parent --format='%H %ct %P'` (newest first). */
export function parseFirstParentList(text: string): FirstParentCommit[] {
  const out: FirstParentCommit[] = [];
  for (const line of text.split('\n')) {
    const [sha, ct, parent] = line.trim().split(' ');
    if (!sha) continue;
    const t = Number(ct);
    if (!SHA_RE.test(sha) || !Number.isSafeInteger(t)) throw new GitError(`unexpected git log line: ${line.slice(0, 200)}`);
    out.push({ sha, ct: t, parent: parent && SHA_RE.test(parent) ? parent : null });
  }
  return out;
}

/** Parse the `-z --name-only --format=%x01%H` walk: commit SHA → paths it added. */
export function parseAddedWalk(text: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const chunk of text.split('\x01')) {
    if (chunk === '') continue;
    const nul = chunk.indexOf('\0');
    const sha = (nul === -1 ? chunk : chunk.slice(0, nul)).trim();
    if (!SHA_RE.test(sha)) throw new GitError(`unexpected git log record: ${chunk.slice(0, 200)}`);
    const paths = nul === -1 ? [] : chunk.slice(nul + 1).replace(/^\n/, '').split('\0').filter((p) => p !== '');
    out.set(sha, paths);
  }
  return out;
}

/**
 * Landing time per commit, oldest first: the committer time, never earlier than the previous
 * commit's landing (`floorMs`) and never later than `nowMs`.
 */
export function landingTimes(oldestFirst: readonly FirstParentCommit[], floorMs: number | null, nowMs: number): Map<string, number> {
  const out = new Map<string, number>();
  let floor = floorMs ?? Number.NEGATIVE_INFINITY;
  for (const c of oldestFirst) {
    const t = Math.min(Math.max(c.ct * 1000, floor), nowMs);
    out.set(c.sha, t);
    floor = t;
  }
  return out;
}

/**
 * Merge the additions of one walk into `dates`, keeping the earliest landing per CVE. With
 * `batchAt`, every addition gets that time instead (used when main's first-parent chain did not
 * run through the previous head, so the commit times of this batch cannot be trusted).
 * Returns how many CVEs got a new or earlier date.
 */
export function mergeLandings(
  dates: Map<string, NucleiAdded>,
  added: ReadonlyMap<string, readonly string[]>,
  landed: ReadonlyMap<string, number>,
  batchAt: number | null = null,
): number {
  let changed = 0;
  for (const [sha, paths] of added) {
    const t = batchAt ?? landed.get(sha);
    if (t === undefined) continue;
    const at = new Date(t).toISOString();
    for (const p of paths) {
      const id = cveFromTemplatePath(p);
      if (!id) continue;
      const prev = dates.get(id);
      // Ties keep the commit seen first; the walk is oldest first, so that is the older commit.
      if (!prev || at < prev.at) {
        dates.set(id, { at, commit: sha });
        changed++;
      }
    }
  }
  return changed;
}

// ── Dates file ─────────────────────────────────────────────────────────────────────────────

const isIso = (v: unknown): v is string => typeof v === 'string' && !Number.isNaN(Date.parse(v)) && /^\d{4}-\d{2}-\d{2}T/.test(v);

/** Read the cached dates file. Null when missing, unreadable or not ours. Never throws. */
export async function readDatesFile(file: string): Promise<NucleiDatesFile | null> {
  try {
    const doc = JSON.parse(await readFile(file, 'utf8')) as Partial<NucleiDatesFile>;
    if (doc?.version !== 1 || doc.remote !== NUCLEI.remote || doc.branch !== NUCLEI.branch) return null;
    if (typeof doc.head !== 'string' || !SHA_RE.test(doc.head) || !isIso(doc.head_at) || !isIso(doc.landed) || !doc.dates || typeof doc.dates !== 'object') return null;
    for (const [id, v] of Object.entries(doc.dates)) {
      if (normalizeCveId(id) !== id || !Array.isArray(v) || !isIso(v[0]) || typeof v[1] !== 'string' || !SHA_RE.test(v[1])) return null;
    }
    return doc as NucleiDatesFile;
  } catch {
    return null;
  }
}

export function datesMap(file: NucleiDatesFile): Map<string, NucleiAdded> {
  return new Map(Object.entries(file.dates).map(([id, [at, commit]]) => [id, { at, commit }]));
}

async function writeDatesFile(file: string, doc: NucleiDatesFile): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  await writeFile(tmp, JSON.stringify(doc));
  await rename(tmp, file);
}

// ── Walking a clone ────────────────────────────────────────────────────────────────────────

interface GitOpts {
  timeoutMs: number;
  signal?: AbortSignal;
}

async function succeeds(args: readonly string[], cwd: string, o: GitOpts): Promise<boolean> {
  try {
    await git(args, { cwd, timeoutMs: o.timeoutMs, signal: o.signal });
    return true;
  } catch {
    return false;
  }
}

async function isShallow(dir: string, o: GitOpts): Promise<boolean> {
  return (await git(['rev-parse', '--is-shallow-repository'], { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal })) === 'true';
}

export interface WalkOutcome {
  dates: Map<string, NucleiAdded>;
  head: string;
  headAt: string;
  landed: string;
  /** "full", "incremental", "unchanged", or "batch" (the chain skipped the previous head). */
  mode: 'full' | 'incremental' | 'unchanged' | 'batch';
  commits: number;
  changed: number;
}

/**
 * Bring `prev` up to `head` in the clone at `dir`: walk only the first-parent commits after
 * `prev.head` when it is an ancestor of `head`, else (no previous dates, or history rewritten)
 * walk the whole first-parent history, which needs a complete (not shallow) clone.
 * `unshallow` is called once when the clone lacks history it needs; it returns false when it
 * cannot deepen the clone. Throws GitError when the walk cannot be done.
 */
export async function walkHistory(
  dir: string,
  head: string,
  prev: NucleiDatesFile | null,
  o: GitOpts & { nowMs: number; unshallow: () => Promise<boolean> },
): Promise<WalkOutcome> {
  const run = (args: readonly string[]) => git(args, { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal });
  const headAt = new Date(Number(await run(['show', '-s', '--format=%ct', head])) * 1000).toISOString();
  if (prev && prev.head === head) {
    return { dates: datesMap(prev), head, headAt: prev.head_at, landed: prev.landed, mode: 'unchanged', commits: 0, changed: 0 };
  }
  let base: NucleiDatesFile | null = null;
  if (prev) {
    const have = async () => (await succeeds(['cat-file', '-e', `${prev.head}^{commit}`], dir, o)) && (await succeeds(['merge-base', '--is-ancestor', prev.head, head], dir, o));
    let ok = await have();
    if (!ok && (await isShallow(dir, o)) && (await o.unshallow())) ok = await have();
    base = ok ? prev : null;
  }
  if (!base && (await isShallow(dir, o)) && !(await o.unshallow())) {
    throw new GitError('the clone is shallow and the full history is needed');
  }
  const range = base ? `${base.head}..${head}` : head;
  const list = parseFirstParentList(await run(['log', '--first-parent', '--format=%H %ct %P', range])).reverse();
  const added = parseAddedWalk(
    await run(['-c', 'core.quotePath=false', 'log', '--first-parent', '--diff-merges=first-parent', '--no-renames', '--diff-filter=A', '--name-only', '-z', '--format=%x01%H', range]),
  );
  // Oldest first, so that ties keep the older commit.
  const ordered = new Map(list.filter((c) => added.has(c.sha)).map((c) => [c.sha, added.get(c.sha)!]));
  const landed = landingTimes(list, base ? Date.parse(base.landed) : null, o.nowMs);
  const dates = base ? datesMap(base) : new Map<string, NucleiAdded>();
  // When main's first parents do not run through the previous head (someone pushed a branch that
  // had main merged into it), the batch's own commit times are branch times: date it by its newest.
  const skipped = base !== null && list.length > 0 && list[0].parent !== base.head;
  const newest = list.length > 0 ? landed.get(list[list.length - 1].sha)! : Date.parse(base?.landed ?? headAt);
  const changed = mergeLandings(dates, ordered, landed, skipped ? newest : null);
  return {
    dates,
    head,
    headAt,
    landed: new Date(newest).toISOString(),
    mode: !base ? 'full' : skipped ? 'batch' : 'incremental',
    commits: list.length,
    changed,
  };
}

// ── The source ─────────────────────────────────────────────────────────────────────────────

export interface NucleiHistoryOptions {
  cacheDir: string;
  offline: boolean;
  log: Logger;
  limits: SanityLimits;
  /** An existing clone to read (never fetched or modified). */
  repoDir?: string;
  /** Overrides for tests. */
  remote?: string;
  shallowDepth?: number;
  now?: () => number;
  signal?: AbortSignal;
}

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err));

async function headOf(dir: string, o: GitOpts): Promise<string | null> {
  try {
    if (!(await stat(dir)).isDirectory()) return null;
    return await git(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}'], { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal });
  } catch {
    return null;
  }
}

/**
 * Fetch the branch into the cache clone (cloning it if missing: shallow when there are cached
 * dates to continue from, else the whole history) and return its new head.
 */
async function syncClone(dir: string, remote: string, depth: number | null, o: GitOpts): Promise<string> {
  const current = await headOf(dir, o);
  if (current) {
    // Follow a changed remote; the fetch keeps the clone's blob filter (set per remote by the clone).
    const url = await git(['config', '--get', 'remote.origin.url'], { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal }).catch(() => '');
    if (url !== remote) await git(['remote', 'set-url', 'origin', remote], { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal });
    await git(['fetch', '--no-tags', 'origin', NUCLEI.branch], { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal });
    const fetched = await git(['rev-parse', '--verify', 'FETCH_HEAD^{commit}'], { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal });
    if (fetched !== current) await git(['update-ref', 'HEAD', fetched], { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal });
    return fetched;
  }
  const tmp = path.resolve(`${dir}.tmp-${process.pid}`);
  await rm(tmp, { recursive: true, force: true });
  await mkdir(path.dirname(dir), { recursive: true });
  const shallow = depth ? ['--depth', String(depth)] : [];
  try {
    await git(['clone', '--quiet', '--filter=blob:none', '--no-checkout', '--single-branch', '--no-tags', '--branch', NUCLEI.branch, ...shallow, remote, tmp], {
      cwd: path.dirname(dir),
      timeoutMs: o.timeoutMs,
      signal: o.signal,
    });
    await rm(dir, { recursive: true, force: true });
    await rename(tmp, dir);
  } catch (err) {
    await rm(tmp, { recursive: true, force: true });
    throw err;
  }
  return git(['rev-parse', '--verify', 'HEAD^{commit}'], { cwd: dir, timeoutMs: o.timeoutMs, signal: o.signal });
}

/**
 * Landing dates of the first Nuclei template per CVE. Never throws. Online it syncs the cache
 * clone and walks the new commits; offline, or when the fetch fails, it walks whatever the local
 * clone has (or keeps the cached dates) and says the result is stale. A `repoDir` is read as is.
 */
export async function loadNucleiDates(opts: NucleiHistoryOptions): Promise<NucleiDatesResult> {
  const { log, signal } = opts;
  const started = performance.now();
  const o: GitOpts = { timeoutMs: NUCLEI.gitTimeoutMs, signal };
  const file = path.join(opts.cacheDir, 'sources', NUCLEI.datesFile);
  const dir = opts.repoDir ?? path.join(opts.cacheDir, 'git', NUCLEI.historyDir);
  const remote = opts.remote ?? NUCLEI.remote;
  const prev = await readDatesFile(file);
  const cached = (error: string | null): NucleiDatesResult =>
    prev ? { dates: datesMap(prev), head: prev.head, stale: true, error } : { dates: null, head: null, stale: true, error: error ?? 'no cached template dates' };

  let head: string | null = null;
  let stale = opts.offline && !opts.repoDir;
  let fetchError: string | null = null;
  if (opts.repoDir || opts.offline) {
    head = await headOf(dir, o);
  } else {
    try {
      head = await syncClone(dir, remote, prev ? (opts.shallowDepth ?? NUCLEI.shallowDepth) : null, o);
    } catch (err) {
      fetchError = errorText(err);
      log.warn(`nuclei-dates: fetch failed (${fetchError})`);
      stale = true;
      head = await headOf(dir, o);
    }
  }
  if (!head) {
    const why = fetchError ?? (opts.repoDir ? `${opts.repoDir} is not a git repository` : 'offline and no local clone');
    if (prev) log.warn(`nuclei-dates: using the cached dates (${why})`);
    else log.error(`nuclei-dates: no template dates (${why})`);
    return cached(fetchError ?? (opts.offline ? null : why));
  }

  let outcome: WalkOutcome;
  try {
    outcome = await walkHistory(dir, head, prev, {
      ...o,
      nowMs: (opts.now ?? Date.now)(),
      unshallow: async () => {
        if (opts.repoDir || opts.offline || fetchError) return false;
        await git(['fetch', '--unshallow', '--no-tags', 'origin', NUCLEI.branch], { cwd: dir, timeoutMs: o.timeoutMs, signal });
        return true;
      },
    });
  } catch (err) {
    const message = `walking the history failed: ${errorText(err)}`;
    log.error(`nuclei-dates: ${message}`);
    return cached(message);
  }
  if (outcome.dates.size < opts.limits.nucleiDates) {
    const message = `only ${outcome.dates.size.toLocaleString('en-US')} CVEs with a template date (expected at least ${opts.limits.nucleiDates.toLocaleString('en-US')})`;
    log.error(`nuclei-dates: ${message}`);
    return cached(message);
  }
  if (outcome.mode !== 'unchanged') {
    const doc: NucleiDatesFile = {
      version: 1,
      remote: NUCLEI.remote,
      branch: NUCLEI.branch,
      head: outcome.head,
      head_at: outcome.headAt,
      landed: outcome.landed,
      updated_at: new Date((opts.now ?? Date.now)()).toISOString(),
      dates: Object.fromEntries([...outcome.dates].sort(([a], [b]) => a.localeCompare(b)).map(([id, d]) => [id, [d.at, d.commit]])),
    };
    try {
      await writeDatesFile(file, doc);
    } catch (err) {
      log.warn(`nuclei-dates: could not write ${file} (${errorText(err)})`);
    }
  }
  log.info(
    `nuclei-dates: ${outcome.dates.size.toLocaleString('en-US')} CVEs dated at ${head.slice(0, 12)} ` +
      `(${outcome.mode}, ${outcome.commits.toLocaleString('en-US')} commits walked, ${outcome.changed} new or earlier) in ${since(started)}${stale ? ' (stale)' : ''}`,
  );
  return { dates: outcome.dates, head, stale, error: fetchError };
}
