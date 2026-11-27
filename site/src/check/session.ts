/**
 * The Check page without the DOM, so its privacy rules can be tested in node.
 *
 * - `touch()` starts the two requests the feature makes, for packages.json and packages-older.json,
 *   on the first interaction with the input card: before any file is read, so neither their timing
 *   nor their URLs depend on the file. Later calls reuse them; only `retry()` asks again. Without
 *   packages-older.json (older data, or a failed load) the check covers the tracked CVEs only.
 * - `run()` parses and matches in memory. It makes no request and writes no storage, history or
 *   URL. A failed index load is reported, not retried behind the user's back.
 * - `runRepo()` checks a public GitHub repository the user named: its requests go to GitHub only
 *   (api.github.com to list the files, raw.githubusercontent.com to read them, see repo.ts), never
 *   to CVErdict, and the files are matched in memory exactly as a dropped file.
 * - The last result is kept in this module (memory only) until `clear()` or a reload, so opening a
 *   CVE from the results and going Back shows them again.
 */
import { rowsFromTable, type PackagesFile } from '../../../shared/contract';
import { mergePackageFiles } from '../../../shared/packages';
import { data, DataError, type DataClient } from '../data';
import { checkComponents, type CheckResult } from './match';
import { parse, ParseError, type FormatId, type Parsed } from './parse';
import { fetchRepoFiles, parseRepo, repoLabel, RepoError } from './repo';

export const FILE_MAX = 50 * 1024 * 1024;
export const PASTE_MAX = 5 * 1024 * 1024;

/**
 * 83886080 → "80 MB", 5452595 → "5.2 MB", 300 → "1 KB". Megabytes round up, so a size just over a
 * limit never reads as the limit itself ("This file is 50 MB. Files up to 50 MB…").
 */
export function fmtSize(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  if (mb < 1) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  // The small offset keeps float noise (6.1 × 1024² is 6.1000000000000005 MB) from rounding up.
  return `${mb >= 10 ? Math.ceil(mb - 1e-9) : Math.ceil(mb * 10 - 1e-9) / 10} MB`;
}

export type Failure =
  | { kind: 'file-too-large'; size: number }
  | { kind: 'paste-too-large'; size: number }
  | { kind: 'parse'; error: ParseError }
  | { kind: 'index'; notPublished: boolean; error: Error }
  | { kind: 'repo'; error: RepoError };

export interface Held {
  result: CheckResult;
  /** File name, or null for pasted text; "owner/repo@branch" for a repository. */
  file: string | null;
  /** For a repository: what was read from it. */
  repo?: RepoSource;
}

export interface RepoSource {
  /** owner/repo as asked, and the branch or commit that was read. */
  name: string;
  ref: string;
  files: { path: string; format: FormatId; packages: number }[];
  /** Files that were found but could not be read, with the parser's message. */
  unread: { path: string; message: string }[];
  /** Files over the cap, and whether GitHub cut a very large tree short. */
  skipped: number;
  truncated: boolean;
  /** Set when only the root could be tried (GitHub's API limit). */
  rootOnly: string | null;
}

export type Stage = { stage: 'parsed'; packages: number } | { stage: 'waiting'; packages: number } | { stage: 'fetching'; repo: string };

export interface RunOptions {
  /** A "Read as" choice; null detects the format. */
  forced?: FormatId | null;
  /** Called between the steps, so the page can say what is happening. */
  onStage?: (s: Stage) => void;
}

export interface RepoRunOptions {
  onStage?: (s: Stage) => void;
  /** For tests: the fetch GitHub's files are read with. */
  fetch?: typeof fetch;
}

export type Outcome = { ok: true; held: Held } | { ok: false; failure: Failure };

export interface CheckSession {
  touch(): Promise<PackagesFile>;
  /** Forget a failed load and request the index again (the Retry button). */
  retry(): Promise<PackagesFile>;
  /** The index once it has loaded: packages.json merged with packages-older.json. */
  index(): PackagesFile | undefined;
  /** Once loaded: whether packages-older.json was in it, and the CVEs it added (no CVE page). */
  older(): { loaded: boolean; ids: ReadonlySet<string> } | null;
  /** Whether touch() has started the load. */
  started(): boolean;
  run(text: string, file: string | null, opts?: RunOptions): Promise<Outcome>;
  /** Check a public GitHub repository: "owner/repo" or its URL. */
  runRepo(input: string, opts?: RepoRunOptions): Promise<Outcome>;
  held(): Held | null;
  clear(): void;
}

/** A paste over 5 MB is refused whole, never cut: a truncated lockfile would silently drop packages. */
export const pasteTooLarge = (length: number): Failure | null => (length > PASTE_MAX ? { kind: 'paste-too-large', size: length } : null);
export const fileTooLarge = (size: number): Failure | null => (size > FILE_MAX ? { kind: 'file-too-large', size } : null);

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/**
 * Every character beyond ASCII in the index's rows and advisory data. The page loads the web font
 * subsets for these as soon as the index arrives, before any file is read: which rows a file
 * matches then never decides whether a font subset is fetched (rows render titles and vendors in
 * the web fonts, and those fonts are split by unicode-range).
 */
export function indexGlyphs(file: Pick<PackagesFile, 'cves' | 'packages'>): string {
  const seen = new Set<string>();
  for (const ch of JSON.stringify([file.cves.rows, file.packages])) if (ch > '\u007e') seen.add(ch);
  return [...seen].sort().join('');
}

/** The index, or the failure to report; waits a tick so the page can say "Checking..." first. */
async function indexOrFailure(index: Promise<PackagesFile>): Promise<PackagesFile | { ok: false; failure: Failure }> {
  try {
    const [pkgs] = await Promise.all([index, tick()]);
    return pkgs;
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    return { ok: false, failure: { kind: 'index', notPublished: e instanceof DataError && e.status === 404, error } };
  }
}

export function createSession(client: Pick<DataClient, 'packages'> & Partial<Pick<DataClient, 'packagesOlder'>>): CheckSession {
  let loading: Promise<PackagesFile> | null = null;
  let merged: PackagesFile | undefined;
  let olderIds: ReadonlySet<string> = new Set();
  let olderLoaded = false;
  let held: Held | null = null;
  const touch = (): Promise<PackagesFile> => {
    if (!loading) {
      // Both requests start together; a missing or failed older file only narrows the check.
      const tracked = client.packages.load();
      const older = client.packagesOlder ? client.packagesOlder.load().catch(() => null) : Promise.resolve(null);
      loading = Promise.all([tracked, older]).then(([tracked, o]) => {
        const ids = new Set(rowsFromTable(tracked.cves).map((r) => r.id));
        olderIds = new Set(o ? rowsFromTable(o.cves).map((r) => r.id).filter((id) => !ids.has(id)) : []);
        olderLoaded = o !== null;
        merged = mergePackageFiles(tracked, o);
        return merged;
      });
      // The page reads the outcome when it needs it; an unobserved failure is not an error here.
      loading.catch(() => undefined);
    }
    return loading;
  };
  return {
    touch,
    retry() {
      // A request that is still hanging is dropped too, so Retry really asks again.
      client.packages.forget?.();
      client.packagesOlder?.forget?.();
      loading = null;
      merged = undefined;
      return touch();
    },
    index: () => merged,
    older: () => (merged ? { loaded: olderLoaded, ids: olderIds } : null),
    started: () => loading !== null,
    async run(text, file, opts = {}) {
      const big = file === null ? pasteTooLarge(text.length) : null;
      if (big) return { ok: false, failure: big };
      const index = touch();
      let parsed;
      try {
        parsed = parse(text, file ?? '', opts.forced ?? null);
      } catch (e) {
        if (e instanceof ParseError) return { ok: false, failure: { kind: 'parse', error: e } };
        throw e;
      }
      const packages = parsed.components.length;
      opts.onStage?.({ stage: merged ? 'parsed' : 'waiting', packages });
      const pkgs = await indexOrFailure(index);
      if (!('cves' in pkgs)) return pkgs;
      held = { result: checkComponents(parsed, pkgs), file };
      return { ok: true, held };
    },
    async runRepo(input, opts = {}) {
      const ref = parseRepo(input);
      if (!ref) return { ok: false, failure: { kind: 'repo', error: new RepoError('invalid', 'Enter a public GitHub repository as owner/repo, or paste its github.com address.') } };
      const index = touch();
      opts.onStage?.({ stage: 'fetching', repo: repoLabel(ref) });
      let got;
      try {
        got = await fetchRepoFiles(ref, opts.fetch ?? fetch);
      } catch (e) {
        if (e instanceof RepoError) return { ok: false, failure: { kind: 'repo', error: e } };
        throw e;
      }
      const components: Parsed['components'] = [];
      const notes: string[] = [];
      const files: RepoSource['files'] = [];
      const unread: RepoSource['unread'] = [];
      for (const f of got.files) {
        try {
          const p = parse(f.text, f.path);
          components.push(...p.components);
          for (const n of p.notes) notes.push(`${f.path}: ${n}`);
          files.push({ path: f.path, format: p.format, packages: p.components.length });
        } catch (e) {
          if (!(e instanceof ParseError)) throw e;
          unread.push({ path: f.path, message: e.kind === 'json' ? 'This looks like JSON, but it could not be read.' : e.message });
        }
      }
      if (!files.length) {
        return { ok: false, failure: { kind: 'repo', error: new RepoError('no-files', `${got.files.length === 1 ? 'The one lockfile' : `None of the ${got.files.length} lockfiles and SBOMs`} found in ${repoLabel(ref)} could be read.`) } };
      }
      opts.onStage?.({ stage: merged ? 'parsed' : 'waiting', packages: components.length });
      const pkgs = await indexOrFailure(index);
      if (!('cves' in pkgs)) return pkgs;
      const result = checkComponents({ format: files[0].format, components, notes }, pkgs);
      held = {
        result,
        file: `${ref.owner}/${ref.repo}@${got.ref}`,
        repo: { name: `${ref.owner}/${ref.repo}`, ref: got.ref, files, unread, skipped: got.skipped, truncated: got.truncated, rootOnly: got.rootOnly },
      };
      return { ok: true, held };
    },
    held: () => held,
    clear() {
      held = null;
    },
  };
}

/** The page's session: one per tab, in memory. */
export const session: CheckSession = createSession(data);
