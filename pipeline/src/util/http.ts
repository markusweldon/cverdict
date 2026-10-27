/**
 * Source downloads with a last-good cache.
 *
 * For each source: try every URL in order (primary, then fallbacks) with a timeout, retries with
 * backoff and conditional GET (stored ETag / Last-Modified); parse and sanity-check the body; only
 * then write it to `<cache>/sources/<key>.<ext>` + `<key>.meta.json`. If every URL fails, the
 * last good cached copy is served and marked stale. `offline` never touches the network.
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { HTTP_RETRY_DELAYS_MS, HTTP_TIMEOUT_MS, USER_AGENT } from '../config';
import type { Logger } from '../types';
import { asNumber, asObject, asString } from './json';
import { formatBytes } from './log';

/** Sidecar describing the cached body. */
export interface CacheMeta {
  url: string;
  etag: string | null;
  last_modified: string | null;
  /** When the body was last confirmed current (downloaded, or revalidated with a 304). */
  fetched_at: string;
  bytes: number;
  records: number | null;
  upstream_version: string | null;
}

/** What a source parser returns for a body that passed its sanity checks. */
export interface Parsed<T> {
  value: T;
  records: number;
  version: string | null;
}

export interface SourceRequest<T> {
  /** Cache file stem, e.g. "kev". */
  key: string;
  /** Cache file extension, e.g. "json" or "csv.gz". */
  ext: string;
  /** Primary first, then fallbacks. */
  urls: readonly string[];
  /** Parse and sanity-check a body; throw to reject it. `cached` describes the last good copy. */
  parse: (body: Buffer, cached: CacheMeta | null) => Parsed<T>;
  /** Serve the cached copy without any request while it is younger than this (rate-limited hosts). */
  minIntervalMs?: number;
  signal?: AbortSignal;
}

export interface SourceFetch<T> {
  /** Null when neither the network nor the cache produced a valid copy. */
  value: T | null;
  /** URL the data came from (for cached copies: the URL it was originally downloaded from). */
  url: string | null;
  fetchedAt: string | null;
  /** Served from cache because live fetches failed (or `offline`). */
  stale: boolean;
  records: number | null;
  version: string | null;
  error: string | null;
}

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface HttpClientOptions {
  cacheDir: string;
  offline: boolean;
  log: Logger;
  fetch?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  /** Wall clock (ms) for cache ages and `fetched_at`; deliberately not the run's frozen `now`. */
  clock?: () => number;
  timeoutMs?: number;
  retryDelaysMs?: readonly number[];
}

class HttpStatusError extends Error {
  constructor(readonly status: number) {
    super(`HTTP ${status}`);
  }
}

/** Network errors, timeouts, rate limiting and server errors are retried; other statuses are final. */
function isRetryable(err: unknown): boolean {
  if (!(err instanceof HttpStatusError)) return true;
  return err.status === 408 || err.status === 425 || err.status === 429 || err.status >= 500;
}

function describe(err: unknown): string {
  if (!(err instanceof Error)) return String(err);
  if (err.name === 'TimeoutError') return 'timed out';
  const cause = (err as Error & { cause?: unknown }).cause;
  return cause instanceof Error && cause.message ? `${err.message}: ${cause.message}` : err.message;
}

type Download = { kind: 'body'; body: Buffer; etag: string | null; lastModified: string | null } | { kind: 'not-modified' };

interface CachedCopy {
  meta: CacheMeta | null;
  body: Buffer;
}

export class HttpClient {
  private readonly dir: string;
  private readonly fetchImpl: FetchLike;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly clock: () => number;
  private readonly timeoutMs: number;
  private readonly retryDelaysMs: readonly number[];

  constructor(private readonly options: HttpClientOptions) {
    this.dir = path.join(options.cacheDir, 'sources');
    this.fetchImpl = options.fetch ?? ((url, init) => fetch(url, init));
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.clock = options.clock ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? HTTP_TIMEOUT_MS;
    this.retryDelaysMs = options.retryDelaysMs ?? HTTP_RETRY_DELAYS_MS;
  }

  /** Fetch, validate and cache one source. Never throws: failures are reported in the result. */
  async getSource<T>(req: SourceRequest<T>): Promise<SourceFetch<T>> {
    const { log } = this.options;
    const cached = await this.readCache(req);
    const errors: string[] = [];

    if (this.options.offline) return this.fromCache(req, cached, null);

    if (cached?.meta && req.minIntervalMs !== undefined) {
      const age = this.clock() - Date.parse(cached.meta.fetched_at);
      if (age >= 0 && age < req.minIntervalMs) {
        const reused = this.tryParse(req, cached);
        if (reused.ok) {
          log.info(`${req.key}: reusing cached copy (${Math.round(age / 60_000)} min old, refetch every ${req.minIntervalMs / 3_600_000}h)`);
          return { ...reused.result, stale: false };
        }
      }
    }

    for (const url of req.urls) {
      if (req.signal?.aborted) break;
      const conditional = cached?.meta?.url === url && cached.meta.bytes === cached.body.length ? cached.meta : null;
      const started = performance.now();
      try {
        const download = await this.download(url, conditional, req.signal);
        const fetchedAt = new Date(this.clock()).toISOString();
        const elapsed = `${((performance.now() - started) / 1000).toFixed(1)}s`;
        if (download.kind === 'not-modified' && cached && conditional) {
          const parsed = req.parse(cached.body, cached.meta);
          await this.writeMeta(req, { ...conditional, fetched_at: fetchedAt });
          log.info(`${req.key}: ${url} not modified (${elapsed})`);
          return { value: parsed.value, url, fetchedAt, stale: false, records: parsed.records, version: parsed.version, error: null };
        }
        if (download.kind === 'not-modified') throw new Error('unexpected 304 without a cached copy');
        const parsed = req.parse(download.body, cached?.meta ?? null);
        await this.writeCache(req, download.body, {
          url,
          etag: download.etag,
          last_modified: download.lastModified,
          fetched_at: fetchedAt,
          bytes: download.body.length,
          records: parsed.records,
          upstream_version: parsed.version,
        });
        log.info(`${req.key}: ${url} → ${formatBytes(download.body.length)}, ${parsed.records.toLocaleString('en-US')} records (${elapsed})`);
        return { value: parsed.value, url, fetchedAt, stale: false, records: parsed.records, version: parsed.version, error: null };
      } catch (err) {
        const message = `${url}: ${describe(err)}`;
        errors.push(message);
        log.warn(`${req.key}: ${message}`);
      }
    }
    return this.fromCache(req, cached, errors.join('; '));
  }

  /** Serve the last good copy. `failure` says why the network was not used; null means offline by choice. */
  private fromCache<T>(req: SourceRequest<T>, cached: CachedCopy | null, failure: string | null): SourceFetch<T> {
    const { log } = this.options;
    const why = failure ?? 'offline';
    const unusable = (detail: string): SourceFetch<T> => {
      log.error(`${req.key}: no usable copy (${why}; ${detail})`);
      return { value: null, url: req.urls[0] ?? null, fetchedAt: null, stale: true, records: null, version: null, error: `${why}; ${detail}` };
    };
    if (!cached) return unusable('no cached copy');
    const reused = this.tryParse(req, cached);
    if (!reused.ok) return unusable(`cached copy unusable: ${reused.error}`);
    log[failure ? 'warn' : 'info'](`${req.key}: using cached copy from ${reused.result.fetchedAt ?? 'an unknown time'}`);
    return { ...reused.result, error: failure };
  }

  private tryParse<T>(req: SourceRequest<T>, cached: CachedCopy): { ok: true; result: SourceFetch<T> } | { ok: false; error: string } {
    try {
      const parsed = req.parse(cached.body, cached.meta);
      return {
        ok: true,
        result: {
          value: parsed.value,
          url: cached.meta?.url ?? req.urls[0] ?? null,
          fetchedAt: cached.meta?.fetched_at ?? null,
          stale: true,
          records: parsed.records,
          version: parsed.version,
          error: null,
        },
      };
    } catch (err) {
      return { ok: false, error: describe(err) };
    }
  }

  /** GET with timeout and retries (2 s, 4 s, 8 s by default) on network errors and 408/429/5xx. */
  private async download(url: string, conditional: CacheMeta | null, signal?: AbortSignal): Promise<Download> {
    const headers: Record<string, string> = { 'user-agent': USER_AGENT, accept: '*/*' };
    if (conditional?.etag) headers['if-none-match'] = conditional.etag;
    if (conditional?.last_modified) headers['if-modified-since'] = conditional.last_modified;

    for (let attempt = 0; ; attempt++) {
      try {
        const timeout = AbortSignal.timeout(this.timeoutMs);
        const res = await this.fetchImpl(url, {
          headers,
          redirect: 'follow',
          signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
        });
        if (res.status === 304) {
          await res.body?.cancel();
          return { kind: 'not-modified' };
        }
        if (!res.ok) {
          await res.body?.cancel();
          throw new HttpStatusError(res.status);
        }
        const body = Buffer.from(await res.arrayBuffer());
        return { kind: 'body', body, etag: res.headers.get('etag'), lastModified: res.headers.get('last-modified') };
      } catch (err) {
        const delay = this.retryDelaysMs[attempt];
        if (signal?.aborted || delay === undefined || !isRetryable(err)) throw err;
        this.options.log.warn(`GET ${url} failed (${describe(err)}); retrying in ${delay / 1000}s`);
        await this.sleep(delay);
      }
    }
  }

  private paths(req: SourceRequest<unknown>) {
    const stem = path.join(this.dir, req.key);
    return { body: `${stem}.${req.ext}`, meta: `${stem}.meta.json` };
  }

  private async readCache(req: SourceRequest<unknown>): Promise<CachedCopy | null> {
    const files = this.paths(req);
    let body: Buffer;
    try {
      body = await readFile(files.body);
    } catch {
      return null;
    }
    let meta: CacheMeta | null = null;
    try {
      meta = parseMeta(JSON.parse(await readFile(files.meta, 'utf8')));
    } catch {
      // A body without readable metadata is still a usable last-good copy.
    }
    return { meta, body };
  }

  private async writeCache(req: SourceRequest<unknown>, body: Buffer, meta: CacheMeta): Promise<void> {
    const files = this.paths(req);
    await mkdir(this.dir, { recursive: true });
    await atomicWrite(files.body, body);
    await atomicWrite(files.meta, `${JSON.stringify(meta, null, 2)}\n`);
  }

  private async writeMeta(req: SourceRequest<unknown>, meta: CacheMeta): Promise<void> {
    await atomicWrite(this.paths(req).meta, `${JSON.stringify(meta, null, 2)}\n`);
  }
}

async function atomicWrite(file: string, data: Buffer | string): Promise<void> {
  const tmp = `${file}.tmp-${process.pid}`;
  await writeFile(tmp, data);
  await rename(tmp, file);
}

function parseMeta(value: unknown): CacheMeta | null {
  const o = asObject(value);
  const url = asString(o?.url);
  const fetchedAt = asString(o?.fetched_at);
  if (!o || !url || !fetchedAt || Number.isNaN(Date.parse(fetchedAt))) return null;
  return {
    url,
    etag: asString(o.etag),
    last_modified: asString(o.last_modified),
    fetched_at: fetchedAt,
    bytes: asNumber(o.bytes) ?? -1,
    records: asNumber(o.records),
    upstream_version: asString(o.upstream_version),
  };
}
