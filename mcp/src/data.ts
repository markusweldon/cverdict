/**
 * Reads the published data tree (shared/contract.ts) for the MCP tools.
 *
 * - Bases are tried in order (the data branch on raw.githubusercontent.com, then the site's /data/
 *   rewrite). A 404 is final; 429, 403 and timeouts move that base to the back for 10 minutes;
 *   network errors, refused redirects, 5xx and malformed files fall through to the next base.
 * - Every tool call runs under one deadline (10 s); each attempt must answer with headers within
 *   4 s, and its body must not pause for 4 s. Bodies are capped at 24 MB decoded, which also stops
 *   a compression bomb from a mirror.
 * - Files are checked before use: schema_version, generated_at, and the exact ROW_COLS of row
 *   tables, so no `__proto__` column can reach rowFromColumns.
 * - Parsed files are cached per pipeline run. meta.json is refetched after 300 s (raw and the site
 *   cache for 300 s anyway); any other file is reused while its generated_at matches meta's, and
 *   otherwise refetched at most once per 300 s. When a refresh fails, the last good copy answers
 *   and the answer's data.warning says so.
 * - Nothing runs between calls: no polling, and every timer is cleared when its call ends.
 */
import { ROW_COLS, SCHEMA_VERSION, rowsFromTable, type CveShard, type KevFile, type Meta, type ReceiptsFile, type Row, type WokeFile } from '../../shared/contract';
import { MCP_DATA_BASES, MCP_MSG } from '../../shared/mcp';

/** A failure the tools report to the agent as is (isError: true). */
export class DataError extends Error {
  constructor(
    message: string,
    /** Per-base reasons, e.g. "raw.githubusercontent.com: HTTP 503". */
    readonly reasons: readonly string[] = [],
  ) {
    super(message);
    this.name = 'DataError';
  }
}

/** The file is not on the data branch (HTTP 404). Final: no other base is tried. */
export class DataUnavailable extends DataError {}

/** The file has another schema_version. Final, and never answered from a cached copy. */
export class SchemaMismatch extends DataError {}

class BadData extends Error {}

export interface DataClientOptions {
  /** Base URLs ending in `/v1/`, tried in order. */
  bases: readonly string[];
  fetch?: typeof fetch;
  metaTtlMs?: number;
  attemptTimeoutMs?: number;
  callTimeoutMs?: number;
  maxBytes?: number;
  maxShards?: number;
  shardConcurrency?: number;
  skipMs?: number;
  now?: () => number;
}

type Options = Required<DataClientOptions>;

const DEFAULTS: Omit<Options, 'bases' | 'fetch'> = {
  metaTtlMs: 300_000,
  attemptTimeoutMs: 4_000,
  callTimeoutMs: 10_000,
  maxBytes: 24 * 1024 * 1024,
  maxShards: 64,
  shardConcurrency: 6,
  skipMs: 600_000,
  now: Date.now,
};

interface Entry<T> {
  value: T;
  /** The file's own generated_at. */
  gen: string;
  url: string;
  loadedAt: number;
  checkedAt: number;
  /** Set when the last refresh failed and this copy is older than it should be. */
  warning: string | null;
}

/** Decoded row table, plus a lower-cased haystack per row for search. */
export interface Rows {
  rows: Row[];
  hay: string[];
}

type Parser<T> = (json: Record<string, unknown>) => T;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function need(ok: unknown, why: string): asserts ok {
  if (!ok) throw new BadData(why);
}

export const parse = {
  meta: (j: Record<string, unknown>): Meta => {
    need(isObject(j.window) && Array.isArray(j.sources) && typeof j.knob_default === 'number', 'missing window, sources or knob_default');
    return j as unknown as Meta;
  },
  rows: (j: Record<string, unknown>): Rows => {
    const cols = j.cols;
    need(Array.isArray(cols) && cols.length === ROW_COLS.length && ROW_COLS.every((c, i) => cols[i] === c), 'columns differ from ROW_COLS');
    need(Array.isArray(j.rows) && j.rows.every((r) => Array.isArray(r) && r.length === ROW_COLS.length), 'a row has the wrong length');
    const rows = rowsFromTable({ cols: ROW_COLS, rows: j.rows as unknown[][] });
    return { rows, hay: rows.map((r) => `${r.id} ${r.cna} ${r.v} ${r.p} ${r.t}`.toLowerCase()) };
  },
  shard: (j: Record<string, unknown>): CveShard => {
    need(isObject(j.items), 'items is not an object');
    return j as unknown as CveShard;
  },
  kev: (j: Record<string, unknown>): KevFile => {
    need(Array.isArray(j.entries), 'entries is not a list');
    return j as unknown as KevFile;
  },
  woke: (j: Record<string, unknown>): WokeFile => {
    need(Array.isArray(j.items) && isObject(j.tracking), 'items or tracking missing');
    return j as unknown as WokeFile;
  },
  receipts: (j: Record<string, unknown>): ReceiptsFile => {
    need(isObject(j.forward) && Array.isArray((j.forward as Record<string, unknown>).items), 'forward log missing');
    return j as unknown as ReceiptsFile;
  },
};

const host = (url: string) => new URL(url).host;

function why(e: unknown): string {
  if (e instanceof AttemptTimeout) return e.message;
  if (e instanceof BadData) return `not valid data: ${e.message}`;
  const cause = (e as { cause?: { code?: string; message?: string } })?.cause;
  return cause?.code ?? cause?.message ?? (e instanceof Error ? e.message : String(e));
}

class AttemptTimeout extends Error {}
class Deadline extends Error {}

/** A promise that rejects with the signal's reason once it aborts, and a way to stop listening. */
function whenAborted(signal: AbortSignal): { promise: Promise<never>; off: () => void } {
  let off = () => {};
  const promise = new Promise<never>((_, reject) => {
    if (signal.aborted) return reject(signal.reason);
    const on = () => reject(signal.reason);
    signal.addEventListener('abort', on, { once: true });
    off = () => signal.removeEventListener('abort', on);
  });
  promise.catch(() => {});
  return { promise, off };
}

/**
 * Reads a body up to `max` decoded bytes. Every read races `stop`, so an abort ends the read even
 * when it does not reach the stream itself; `progress` runs before each read (the stall timer).
 */
async function readCapped(res: Response, max: number, stop: Promise<never>, progress: () => void): Promise<string> {
  if (Number(res.headers.get('content-length') ?? '') > max) throw new Error(`body over ${max} bytes`);
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  try {
    for (;;) {
      progress();
      const { done, value } = await Promise.race([reader.read(), stop]);
      if (done) break;
      n += value.byteLength;
      if (n > max) throw new Error(`body over ${max} bytes`);
      chunks.push(value);
    }
  } catch (e) {
    void reader.cancel().catch(() => {});
    throw e;
  }
  return Buffer.concat(chunks, n).toString('utf8');
}

export class DataClient {
  private readonly o: Options;
  private readonly files = new Map<string, Entry<unknown>>();
  /** Least recently inserted first; at most maxShards. */
  private readonly shardCache = new Map<string, Entry<unknown>>();
  /** Fetches in progress, shared by concurrent calls, with the signal of the call that started each. */
  private readonly inflight = new Map<string, { p: Promise<Entry<unknown>>; signal: AbortSignal }>();
  private readonly skipUntil = new Map<string, number>();
  /** Requests sent, for tests and measurements. */
  requests = 0;

  constructor(opts: DataClientOptions) {
    this.o = { ...DEFAULTS, fetch: (input, init) => fetch(input, init), ...opts };
    if (this.o.bases.length === 0) throw new Error('DataClient needs at least one base URL');
  }

  get bases(): readonly string[] {
    return this.o.bases;
  }

  now(): number {
    return this.o.now();
  }

  get shardConcurrency(): number {
    return this.o.shardConcurrency;
  }

  /**
   * Runs one tool call under its deadline. When the call ends, anything it left in flight (a
   * shard fetch after another one failed) is aborted, so nothing keeps running between calls.
   */
  async run<T>(fn: (call: DataCall) => Promise<T>): Promise<T> {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(new Deadline()), this.o.callTimeoutMs);
    try {
      return await fn(new DataCall(this, ac.signal));
    } finally {
      clearTimeout(timer);
      ac.abort(new Deadline());
    }
  }

  /** Bases in order, with the ones that recently answered 429 or 403, or timed out, moved to the back. */
  private orderedBases(): string[] {
    const now = this.o.now();
    const skipped = (b: string) => (this.skipUntil.get(b) ?? 0) > now;
    return [...this.o.bases.filter((b) => !skipped(b)), ...this.o.bases.filter(skipped)];
  }

  /**
   * One GET within the call's deadline: response headers within attemptTimeoutMs, then a body that
   * never pauses for longer than that (a slow body that keeps arriving is fine). The attempt has its
   * own controller, aborted by a listener on the call's signal, and every await races it. Not
   * AbortSignal.any(): its composite signal can be garbage-collected during a long body read, and
   * then no abort reaches the read, which hung the call and every later call that joined its fetch.
   */
  private async get(url: string, signal: AbortSignal): Promise<{ status: number; body: string }> {
    // A call that has ended (or timed out) sends nothing more.
    if (signal.aborted) throw signal.reason;
    const ac = new AbortController();
    const forward = () => ac.abort(signal.reason);
    signal.addEventListener('abort', forward, { once: true });
    const stop = whenAborted(ac.signal);
    const s = this.o.attemptTimeoutMs / 1000;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = (why: string) => {
      clearTimeout(timer);
      timer = setTimeout(() => ac.abort(new AttemptTimeout(why)), this.o.attemptTimeoutMs);
    };
    arm(`timed out after ${s} s`);
    this.requests++;
    let res: Response | undefined;
    try {
      res = await Promise.race([this.o.fetch(url, { signal: ac.signal, redirect: 'error', headers: { accept: 'application/json' } }), stop.promise]);
      if (!res.ok) return { status: res.status, body: '' };
      return { status: res.status, body: await readCapped(res, this.o.maxBytes, stop.promise, () => arm(`stalled for ${s} s`)) };
    } catch (e) {
      throw ac.signal.aborted && !signal.aborted ? ac.signal.reason : e;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', forward);
      stop.off();
      if (res?.body && !res.bodyUsed) void res.body.cancel().catch(() => {});
    }
  }

  private async fetchFile<T>(path: string, parser: Parser<T>, signal: AbortSignal): Promise<Entry<T>> {
    const reasons: string[] = [];
    for (const base of this.orderedBases()) {
      const url = base + path;
      let json: unknown;
      try {
        const res = await this.get(url, signal);
        if (res.status === 404) throw new DataUnavailable(MCP_MSG.notPublished(path));
        if (res.status < 200 || res.status > 299) {
          if (res.status === 429 || res.status === 403) this.skipUntil.set(base, this.o.now() + this.o.skipMs);
          reasons.push(`${host(url)}: HTTP ${res.status} for ${path}`);
          continue;
        }
        json = JSON.parse(res.body);
        need(isObject(json), 'not a JSON object');
        if (json.schema_version !== SCHEMA_VERSION) throw new SchemaMismatch(MCP_MSG.schema(json.schema_version, SCHEMA_VERSION));
        need(typeof json.generated_at === 'string', 'no generated_at');
        const now = this.o.now();
        return { value: parser(json), gen: json.generated_at as string, url, loadedAt: now, checkedAt: now, warning: null };
      } catch (e) {
        if (e instanceof DataError) throw e;
        if (signal.aborted) throw new DataError(MCP_MSG.deadline([...reasons, `${host(url)}: no answer within ${this.o.callTimeoutMs / 1000} s for ${path}`]), reasons);
        // A base that does not answer costs 4 s per file; without this, a call over many shards ran
        // out of time on a base that accepts connections and never answers, every time.
        if (e instanceof AttemptTimeout) this.skipUntil.set(base, this.o.now() + this.o.skipMs);
        reasons.push(`${host(url)}: ${e instanceof SyntaxError ? 'not valid JSON' : why(e)} for ${path}`);
      }
    }
    throw new DataError(MCP_MSG.allFailed(reasons), reasons);
  }

  /**
   * A cached file, refreshed when needed. `gen` is the current meta.generated_at (null for meta
   * itself, which only follows the TTL).
   */
  async load<T>(path: string, parser: Parser<T>, gen: string | null, signal: AbortSignal): Promise<Entry<T>> {
    const cache = path.startsWith('cve/') ? this.shardCache : this.files;
    const hit = cache.get(path) as Entry<T> | undefined;
    const now = this.o.now();
    if (hit && ((gen !== null && hit.gen === gen) || now - hit.checkedAt < this.o.metaTtlMs)) return hit;
    let f = this.inflight.get(path) as { p: Promise<Entry<T>>; signal: AbortSignal } | undefined;
    if (!f) {
      const mine = { p: this.fetchFile(path, parser, signal), signal };
      this.inflight.set(path, mine);
      void mine.p.then(
        (e) => {
          if (this.inflight.get(path) === mine) this.inflight.delete(path);
          cache.delete(path);
          cache.set(path, e);
          if (cache === this.shardCache) for (const k of cache.keys()) if (cache.size > this.o.maxShards) cache.delete(k);
        },
        () => this.inflight.get(path) === mine && this.inflight.delete(path),
      );
      f = mine;
    }
    // A call that joined another call's fetch still answers within its own deadline.
    const joined = f.signal !== signal;
    const stop = joined ? whenAborted(signal) : null;
    try {
      return await (stop ? Promise.race([f.p, stop.promise]) : f.p);
    } catch (err) {
      // That fetch ended with the call that started it (its deadline, or another of its files
      // failed) while this call still has time: fetch again under this call's own deadline.
      if (joined && f.signal.aborted && !signal.aborted && !(err instanceof DataUnavailable) && !(err instanceof SchemaMismatch)) return this.load(path, parser, gen, signal);
      const e = joined && signal.aborted && !(err instanceof DataError) ? new DataError(MCP_MSG.deadline([`no answer within ${this.o.callTimeoutMs / 1000} s for ${path}`])) : err;
      if (!hit || e instanceof DataUnavailable || e instanceof SchemaMismatch || !(e instanceof DataError)) throw e;
      hit.checkedAt = this.o.now();
      hit.warning = MCP_MSG.refreshFailed(e.reasons.length ? e.reasons : ['no answer in time'], new Date(hit.loadedAt).toISOString());
      return hit;
    } finally {
      stop?.off();
    }
  }
}

/** The files one tool call read, for the answer's data block. */
export interface FileRef {
  path: string;
  url: string;
  generated_at: string;
}

/** One tool call: its deadline, the files it read and the warnings they carried. */
export class DataCall {
  readonly files = new Map<string, FileRef>();
  readonly warnings = new Set<string>();
  private metaEntry: Entry<Meta> | null = null;

  constructor(
    private readonly dc: DataClient,
    readonly signal: AbortSignal,
  ) {}

  private use<T>(path: string, e: Entry<T>): T {
    this.files.set(path, { path: `v1/${path}`, url: e.url, generated_at: e.gen });
    if (e.warning) this.warnings.add(e.warning);
    return e.value;
  }

  async meta(): Promise<Meta> {
    this.metaEntry ??= await this.dc.load('meta.json', parse.meta, null, this.signal);
    return this.use('meta.json', this.metaEntry);
  }

  async file<T>(path: string, parser: Parser<T>): Promise<T> {
    const meta = await this.meta();
    return this.use(path, await this.dc.load(path, parser, meta.generated_at, this.signal));
  }

  /** The named shards (two hex digits each), fetched concurrently, a few at a time. */
  async shards(names: readonly string[]): Promise<Map<string, { shard: CveShard; url: string }>> {
    const meta = await this.meta();
    const out = new Map<string, { shard: CveShard; url: string }>();
    const queue = [...new Set(names)];
    const entries = new Map<string, Entry<CveShard>>();
    const worker = async () => {
      for (let name = queue.shift(); name !== undefined; name = queue.shift()) {
        entries.set(name, await this.dc.load(`cve/${name}.json`, parse.shard, meta.generated_at, this.signal));
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.dc.shardConcurrency, queue.length) }, worker));
    for (const name of [...new Set(names)]) {
      const e = entries.get(name)!;
      out.set(name, { shard: this.use(`cve/${name}.json`, e), url: e.url });
    }
    return out;
  }
}

/** CVERDICT_DATA_BASE: comma-separated base URLs. https only, or http on localhost for development. */
export function basesFromEnv(value: string | undefined): string[] {
  if (!value?.trim()) return [...MCP_DATA_BASES];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      let u: URL;
      try {
        u = new URL(s);
      } catch {
        throw new Error(`CVERDICT_DATA_BASE: not a URL: ${s}`);
      }
      const local = u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
      if (u.protocol !== 'https:' && !local) throw new Error(`CVERDICT_DATA_BASE: use https (or http on localhost): ${s}`);
      if (u.username || u.password || u.search || u.hash) throw new Error(`CVERDICT_DATA_BASE: no credentials, query or fragment: ${s}`);
      return u.href.endsWith('/') ? u.href : `${u.href}/`;
    });
}

export function dataClientFromEnv(env: Record<string, string | undefined>): DataClient {
  return new DataClient({ bases: basesFromEnv(env.CVERDICT_DATA_BASE) });
}
