import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { BRAND } from '../../../shared/brand';
import { HttpClient, type FetchLike, type Parsed, type SourceRequest } from '../../src/util/http';
import { captureLogger, tempDir } from './helpers';

/** Parser used by most tests: a JSON array that must have at least `min` items. */
function arrayParser(min = 1) {
  return (body: Buffer): Parsed<number[]> => {
    const value = JSON.parse(body.toString()) as number[];
    if (!Array.isArray(value) || value.length < min) throw new Error(`only ${Array.isArray(value) ? value.length : 0} items`);
    return { value, records: value.length, version: `v${value.length}` };
  };
}

type Route = (attempt: number) => Response | Error;

/** Fetch stub routing by URL; records every call. */
function stubFetch(routes: Record<string, Route>) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const counts = new Map<string, number>();
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, headers: { ...(init.headers as Record<string, string>) } });
    const attempt = (counts.get(url) ?? 0) + 1;
    counts.set(url, attempt);
    const route = routes[url];
    if (!route) throw new TypeError('fetch failed');
    const result = route(attempt);
    if (result instanceof Error) throw result;
    return result;
  };
  return { fetch, calls };
}

const json = (value: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(value), { status: 200, headers });
const status = (code: number) => new Response('nope', { status: code });

function client(opts: { fetch: FetchLike; offline?: boolean; clock?: () => number; cacheDir?: string }) {
  const sleeps: number[] = [];
  const log = captureLogger();
  const cacheDir = opts.cacheDir ?? tempDir();
  const http = new HttpClient({
    cacheDir,
    offline: opts.offline ?? false,
    log,
    fetch: opts.fetch,
    sleep: async (ms) => void sleeps.push(ms),
    clock: opts.clock,
  });
  return { http, sleeps, log, cacheDir };
}

const PRIMARY = 'https://primary.example/feed.json';
const FALLBACK = 'https://fallback.example/feed.json';
const request = (extra: Partial<SourceRequest<number[]>> = {}): SourceRequest<number[]> => ({
  key: 'feed',
  ext: 'json',
  urls: [PRIMARY, FALLBACK],
  parse: arrayParser(),
  ...extra,
});

describe('HttpClient.getSource', () => {
  it('falls back to the next URL on a non-retryable status, without retrying it, and caches the result', async () => {
    const { fetch, calls } = stubFetch({ [PRIMARY]: () => status(403), [FALLBACK]: () => json([1, 2, 3], { etag: '"abc"' }) });
    const { http, sleeps, cacheDir } = client({ fetch, clock: () => Date.parse('2026-10-26T19:30:00Z') });
    const result = await http.getSource(request());
    expect(result).toEqual({ value: [1, 2, 3], url: FALLBACK, fetchedAt: '2026-10-26T19:30:00.000Z', stale: false, records: 3, version: 'v3', error: null });
    expect(calls.map((c) => c.url)).toEqual([PRIMARY, FALLBACK]);
    expect(sleeps).toEqual([]);
    expect(calls[0].headers['user-agent']).toMatch(new RegExp(`^${BRAND.slug}-pipeline \\(\\+https://github\\.com/`));

    const meta = JSON.parse(readFileSync(path.join(cacheDir, 'sources', 'feed.meta.json'), 'utf8'));
    expect(meta).toMatchObject({ url: FALLBACK, etag: '"abc"', records: 3, upstream_version: 'v3', bytes: 7, fetched_at: '2026-10-26T19:30:00.000Z' });
    expect(readFileSync(path.join(cacheDir, 'sources', 'feed.json'), 'utf8')).toBe('[1,2,3]');
  });

  it('retries network errors and 5xx with 2 s, 4 s, 8 s backoff', async () => {
    const { fetch, calls } = stubFetch({
      [PRIMARY]: (n) => (n === 1 ? new TypeError('fetch failed') : n < 4 ? status(503) : json([1])),
    });
    const { http, sleeps } = client({ fetch });
    const result = await http.getSource(request());
    expect(result.value).toEqual([1]);
    expect(calls).toHaveLength(4);
    expect(sleeps).toEqual([2000, 4000, 8000]);
  });

  it('gives up on a URL after 3 retries and moves on', async () => {
    const { fetch, calls } = stubFetch({ [PRIMARY]: () => status(429), [FALLBACK]: () => json([7]) });
    const { http, sleeps } = client({ fetch });
    expect((await http.getSource(request())).value).toEqual([7]);
    expect(calls.filter((c) => c.url === PRIMARY)).toHaveLength(4);
    expect(sleeps).toEqual([2000, 4000, 8000]);
  });

  it('serves the last good cached copy, marked stale, when every URL fails', async () => {
    const cacheDir = tempDir();
    const good = stubFetch({ [PRIMARY]: () => json([1, 2]) });
    await client({ fetch: good.fetch, cacheDir, clock: () => Date.parse('2026-10-25T10:00:00Z') }).http.getSource(request());

    const down = stubFetch({ [PRIMARY]: () => status(404), [FALLBACK]: () => status(500) });
    const { http, log } = client({ fetch: down.fetch, cacheDir });
    const result = await http.getSource(request());
    expect(result).toMatchObject({ value: [1, 2], url: PRIMARY, fetchedAt: '2026-10-25T10:00:00.000Z', stale: true, records: 2 });
    expect(result.error).toBe(`${PRIMARY}: HTTP 404; ${FALLBACK}: HTTP 500`);
    expect(log.lines.some((l) => l.startsWith('WARN feed: using cached copy'))).toBe(true);
  });

  it('never caches a body that fails its sanity check, and falls back to the previous copy', async () => {
    const cacheDir = tempDir();
    await client({ fetch: stubFetch({ [PRIMARY]: () => json([1, 2, 3]) }).fetch, cacheDir }).http.getSource(request());

    const { http } = client({ fetch: stubFetch({ [PRIMARY]: () => json([9]), [FALLBACK]: () => json([]) }).fetch, cacheDir });
    const result = await http.getSource(request({ parse: arrayParser(2) }));
    expect(result).toMatchObject({ value: [1, 2, 3], stale: true });
    expect(result.error).toContain('only 1 items');
    expect(readFileSync(path.join(cacheDir, 'sources', 'feed.json'), 'utf8')).toBe('[1,2,3]');
  });

  it('reports the failure when there is no cached copy', async () => {
    const { http } = client({ fetch: stubFetch({}).fetch });
    const result = await http.getSource(request());
    expect(result).toMatchObject({ value: null, stale: true, records: null, fetchedAt: null });
    expect(result.error).toMatch(/no cached copy$/);
  });

  it('offline: never touches the network', async () => {
    const cacheDir = tempDir();
    await client({ fetch: stubFetch({ [PRIMARY]: () => json([5]) }).fetch, cacheDir }).http.getSource(request());
    const { fetch, calls } = stubFetch({ [PRIMARY]: () => json([6]) });

    const cached = await client({ fetch, cacheDir, offline: true }).http.getSource(request());
    expect(cached).toMatchObject({ value: [5], stale: true, error: null });
    const missing = await client({ fetch, offline: true }).http.getSource(request());
    expect(missing.value).toBeNull();
    expect(calls).toEqual([]);
  });

  it('reuses a cached copy younger than minIntervalMs without a request', async () => {
    const cacheDir = tempDir();
    const t0 = Date.parse('2026-10-26T12:00:00Z');
    await client({ fetch: stubFetch({ [PRIMARY]: () => json([1]) }).fetch, cacheDir, clock: () => t0 }).http.getSource(request());

    const { fetch, calls } = stubFetch({ [PRIMARY]: () => json([1, 2]) });
    const young = await client({ fetch, cacheDir, clock: () => t0 + 3_600_000 }).http.getSource(request({ minIntervalMs: 6 * 3_600_000 }));
    expect(young).toMatchObject({ value: [1], stale: false, fetchedAt: '2026-10-26T12:00:00.000Z' });
    expect(calls).toHaveLength(0);

    const old = await client({ fetch, cacheDir, clock: () => t0 + 7 * 3_600_000 }).http.getSource(request({ minIntervalMs: 6 * 3_600_000 }));
    expect(old).toMatchObject({ value: [1, 2], stale: false });
    expect(calls).toHaveLength(1);
  });

  it('treats a cache body without metadata as a usable fallback', async () => {
    const cacheDir = tempDir();
    await client({ fetch: stubFetch({ [PRIMARY]: () => json([4]) }).fetch, cacheDir }).http.getSource(request());
    writeFileSync(path.join(cacheDir, 'sources', 'feed.meta.json'), '{broken');
    const result = await client({ fetch: stubFetch({}).fetch, cacheDir }).http.getSource(request());
    expect(result).toMatchObject({ value: [4], stale: true, fetchedAt: null, url: PRIMARY });
  });
});

describe('HttpClient against a real HTTP server', () => {
  let server: Server | null = null;
  afterEach(async () => {
    await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
    server = null;
  });

  async function serve(handler: (headers: IncomingHttpHeaders, res: import('node:http').ServerResponse) => void): Promise<string> {
    server = createServer((req, res) => handler(req.headers, res));
    await new Promise<void>((resolve) => server?.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${(server?.address() as AddressInfo).port}/feed.json`;
  }

  it('uses conditional GET: a 304 serves the cached body and refreshes fetched_at', async () => {
    const seen: IncomingHttpHeaders[] = [];
    const url = await serve((headers, res) => {
      seen.push(headers);
      if (headers['if-none-match'] === 'W/"v1"') {
        res.writeHead(304).end();
        return;
      }
      res.writeHead(200, { etag: 'W/"v1"', 'last-modified': 'Mon, 26 Oct 2026 12:00:00 GMT', 'content-type': 'application/json' }).end('[1,2,3,4]');
    });
    const cacheDir = tempDir();
    let now = Date.parse('2026-10-26T12:00:00Z');
    const http = new HttpClient({ cacheDir, offline: false, log: captureLogger(), clock: () => now });
    const req: SourceRequest<number[]> = { key: 'feed', ext: 'json', urls: [url], parse: arrayParser() };

    expect((await http.getSource(req)).value).toEqual([1, 2, 3, 4]);
    now += 3_600_000;
    const second = await http.getSource(req);
    expect(second).toMatchObject({ value: [1, 2, 3, 4], stale: false, fetchedAt: '2026-10-26T13:00:00.000Z' });
    expect(seen[0]['if-none-match']).toBeUndefined();
    expect(seen[1]['if-none-match']).toBe('W/"v1"');
    expect(seen[1]['if-modified-since']).toBe('Mon, 26 Oct 2026 12:00:00 GMT');
    expect(seen[1]['user-agent']).toContain(`${BRAND.slug}-pipeline`);
    const meta = JSON.parse(readFileSync(path.join(cacheDir, 'sources', 'feed.meta.json'), 'utf8'));
    expect(meta.fetched_at).toBe('2026-10-26T13:00:00.000Z');
  });

  it('times out a hanging server and reports it', async () => {
    const url = await serve(() => {
      /* never respond */
    });
    const cacheDir = tempDir();
    const http = new HttpClient({ cacheDir, offline: false, log: captureLogger(), timeoutMs: 200, retryDelaysMs: [] });
    const result = await http.getSource({ key: 'slow', ext: 'json', urls: [url], parse: arrayParser() });
    expect(result.value).toBeNull();
    expect(result.error).toContain('timed out');
    expect(existsSync(path.join(cacheDir, 'sources', 'slow.json'))).toBe(false);
  });
});
