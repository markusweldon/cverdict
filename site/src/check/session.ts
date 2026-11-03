/**
 * The Check page without the DOM, so its privacy rules can be tested in node.
 *
 * - `touch()` starts the one request the feature makes, for packages.json, on the first
 *   interaction with the input card: before any file is read, so neither its timing nor its URL
 *   depends on the file. Later calls reuse it; only `retry()` asks again.
 * - `run()` parses and matches in memory. It makes no request and writes no storage, history or
 *   URL. A failed index load is reported, not retried behind the user's back.
 * - The last result is kept in this module (memory only) until `clear()` or a reload, so opening a
 *   CVE from the results and going Back shows them again.
 */
import type { PackagesFile } from '../../../shared/contract';
import { data, DataError, type DataClient } from '../data';
import { checkComponents, type CheckResult } from './match';
import { parse, ParseError, type FormatId } from './parse';

export const FILE_MAX = 50 * 1024 * 1024;
export const PASTE_MAX = 5 * 1024 * 1024;

/** 83886080 → "80 MB", 5452595 → "5.2 MB", 300 → "1 KB". */
export function fmtSize(bytes: number): string {
  const mb = bytes / (1024 * 1024);
  if (mb < 1) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${mb >= 10 ? Math.round(mb) : Math.round(mb * 10) / 10} MB`;
}

export type Failure =
  | { kind: 'file-too-large'; size: number }
  | { kind: 'paste-too-large'; size: number }
  | { kind: 'parse'; error: ParseError }
  | { kind: 'index'; notPublished: boolean; error: Error };

export interface Held {
  result: CheckResult;
  /** File name, or null for pasted text. */
  file: string | null;
}

export type Stage = { stage: 'parsed'; packages: number } | { stage: 'waiting'; packages: number };

export interface RunOptions {
  /** A "Read as" choice; null detects the format. */
  forced?: FormatId | null;
  /** Called between the steps, so the page can say what is happening. */
  onStage?: (s: Stage) => void;
}

export type Outcome = { ok: true; held: Held } | { ok: false; failure: Failure };

export interface CheckSession {
  touch(): Promise<PackagesFile>;
  /** Forget a failed load and request the index again (the Retry button). */
  retry(): Promise<PackagesFile>;
  /** The index once it has loaded. */
  index(): PackagesFile | undefined;
  /** Whether touch() has started the load. */
  started(): boolean;
  run(text: string, file: string | null, opts?: RunOptions): Promise<Outcome>;
  held(): Held | null;
  clear(): void;
}

/** A paste over 5 MB is refused whole, never cut: a truncated lockfile would silently drop packages. */
export const pasteTooLarge = (length: number): Failure | null => (length > PASTE_MAX ? { kind: 'paste-too-large', size: length } : null);
export const fileTooLarge = (size: number): Failure | null => (size > FILE_MAX ? { kind: 'file-too-large', size } : null);

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

export function createSession(client: Pick<DataClient, 'packages'>): CheckSession {
  let loading: Promise<PackagesFile> | null = null;
  let held: Held | null = null;
  const touch = (): Promise<PackagesFile> => {
    if (!loading) {
      loading = client.packages.load();
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
      loading = null;
      return touch();
    },
    index: () => client.packages.peek(),
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
      opts.onStage?.({ stage: client.packages.peek() ? 'parsed' : 'waiting', packages });
      let pkgs: PackagesFile;
      try {
        // Let the page show "Checking n packages..." before the synchronous matching starts.
        [pkgs] = await Promise.all([index, tick()]);
      } catch (e) {
        const error = e instanceof Error ? e : new Error(String(e));
        return { ok: false, failure: { kind: 'index', notPublished: e instanceof DataError && e.status === 404, error } };
      }
      held = { result: checkComponents(parsed, pkgs), file };
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
