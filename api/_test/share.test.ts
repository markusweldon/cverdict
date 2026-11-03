import { readdirSync, readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RAW_DATA_URL } from '../../shared/brand';
import { shardOf } from '../../shared/shard';
import { BOT_UA_TOKENS, BOT_UA_VALUE, genericHead, injectHead } from '../../shared/share';
import { SHARE_IMAGES } from '../../shared/share-images';
import * as F from '../../shared/share.fixtures';
import { CDN_CACHE_OK, CDN_CACHE_SHORT, createShareHandler, DEADLINE_MS, GET, HEAD, SHARD_MAX_BYTES } from '../share';

const ORIGIN = 'https://cverdict-psi.vercel.app';
const TEMPLATE = injectHead(readFileSync(new URL('../../site/index.html', import.meta.url), 'utf8'), genericHead(ORIGIN));
const ID = 'CVE-2026-109618';
const rawUrl = (id: string) => `${RAW_DATA_URL}/v1/cve/${shardOf(id)}.json`;
const ownUrl = (id: string) => `${ORIGIN}/data/v1/cve/${shardOf(id)}.json`;
const TEMPLATE_URL = `${ORIGIN}/index.html`;

type Answer = Response | Promise<Response> | (() => Response | Promise<Response>);
interface Call {
  url: string;
  headers: Record<string, string>;
}

/** A fetch that answers from `routes` (by URL) and records every call. Unknown URLs get a 404. */
function fakeFetch(routes: Record<string, Answer | Answer[]>) {
  const calls: Call[] = [];
  const fn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, headers: { ...((init?.headers as Record<string, string>) ?? {}) } });
    let route = routes[url];
    if (Array.isArray(route)) route = route.length > 1 ? route.shift()! : route[0];
    if (!route) return new Response('not found', { status: 404 });
    const res = typeof route === 'function' ? route() : route;
    // Honour the abort signal, like the real fetch.
    return await new Promise<Response>((resolve, reject) => {
      const signal = init?.signal;
      if (signal?.aborted) return reject(signal.reason);
      signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
      Promise.resolve(res).then(resolve, reject);
    });
  }) as typeof fetch;
  return { fn, calls, count: (url: string) => calls.filter((c) => c.url === url).length };
}

const html = (body = TEMPLATE) => () => new Response(body, { headers: { 'content-type': 'text/html; charset=utf-8' } });
const json = (value: unknown, headers: Record<string, string> = {}) => () => new Response(JSON.stringify(value), { headers: { 'content-type': 'text/plain; charset=utf-8', ...headers } });
const status = (code: number) => () => new Response('error', { status: code });
const never = () => new Promise<Response>(() => {});
/** A body streamed in 64 KB chunks, without Content-Length unless given. */
function stream(bytes: number, headers: Record<string, string> = {}) {
  return () => {
    let sent = 0;
    const chunk = new Uint8Array(64 * 1024).fill(0x20);
    const body = new ReadableStream<Uint8Array>({
      pull(ctrl) {
        if (sent >= bytes) return ctrl.close();
        sent += chunk.byteLength;
        ctrl.enqueue(chunk);
      },
    });
    const res = new Response(body, { headers });
    return Object.assign(res, { sentBytes: () => sent });
  };
}

const req = (query: string, init?: RequestInit) => new Request(`${ORIGIN}/api/share?${query}`, init);
const shard = F.shardFile(F.EXPLOITED_KEV, F.WATCH);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
  vi.setSystemTime(new Date('2026-11-03T07:00:00Z'));
});
afterEach(() => {
  vi.useRealTimers();
});

describe('api/share', () => {
  it('answers a bot with the CVE’s tags inside the site’s own page', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: json(shard, { etag: '"a1"' }) });
    const res = await createShareHandler({ fetch: f.fn, env: {} })(req(`id=${ID}`));
    const body = await res.text();
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8');
    expect(res.headers.get('cache-control')).toBe('public, max-age=300');
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_OK);
    expect(body).toContain('<title>CVE-2026-109618: Exploited, score 100 · CVErdict</title>');
    expect(body).toContain(`<meta property="og:image" content="${ORIGIN}/og/exploited.png?v=${SHARE_IMAGES.exploited.v}" />`);
    expect(body).toContain('<script type="module" src="/src/main.tsx"></script>');
    expect(body.match(/<title>/g)).toHaveLength(1);
    expect(body.match(/og:title/g)).toHaveLength(1);
    expect(Buffer.byteLength(body)).toBeLessThan(8 * 1024);
    expect(f.calls.map((c) => c.url)).toEqual([TEMPLATE_URL, rawUrl(ID)]);
  });

  it('exports GET and HEAD as one handler', () => {
    expect(GET).toBe(HEAD);
  });

  it('is the only function: Vercel deploys every file in api/ except those under _ or . names', () => {
    const functions = readdirSync(new URL('..', import.meta.url)).filter((f) => !f.startsWith('_') && !f.startsWith('.') && /\.(ts|js|mjs|cjs)$/.test(f));
    expect(functions).toEqual(['share.ts']);
  });

  it('answers HEAD with the headers and no body', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: json(shard) });
    const res = await createShareHandler({ fetch: f.fn, env: {} })(req(`id=${ID}`, { method: 'HEAD' }));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8');
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_OK);
    expect(res.body).toBeNull();
  });

  it('upper-cases a lower-case ID', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: json(shard) });
    const body = await (await createShareHandler({ fetch: f.fn, env: {} })(req('id=cve-2026-109618'))).text();
    expect(body).toContain(`<link rel="canonical" href="${ORIGIN}/cve/CVE-2026-109618" />`);
  });

  it('says "not in the data" with the site card for an ID no shard has', async () => {
    const id = 'CVE-2019-0001';
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(id)]: json(F.shardFile()) });
    const res = await createShareHandler({ fetch: f.fn, env: {} })(req(`id=${id}`));
    const body = await res.text();
    expect(body).toContain('<title>CVE-2019-0001 · CVErdict</title>');
    expect(body).toContain("Not in CVErdict&#39;s data");
    expect(body).toContain(`${ORIGIN}/og/site.png?v=`);
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_OK);
  });

  it('answers a malformed ID, a second id or none with the untouched page, without reading data', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html() });
    const handler = createShareHandler({ fetch: f.fn, env: {} });
    for (const q of ['id=CVE-1', 'id=%3Cscript%3E', `id=CVE-2026-${'1'.repeat(20)}`, `id=${ID}&id=CVE-2019-0001`, `id=CVE-2019-0001&id=${ID}`, '', 'id=']) {
      const res = await handler(req(q));
      expect(await res.text(), q).toBe(TEMPLATE);
      expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_OK);
    }
    expect(f.calls.map((c) => c.url)).toEqual([TEMPLATE_URL]);
  });

  it('builds the same bytes whatever Host and X-Forwarded-Host say', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: json(shard) });
    const handler = createShareHandler({ fetch: f.fn, env: { VERCEL_PROJECT_PRODUCTION_URL: 'cverdict-psi.vercel.app' } });
    const a = await (await handler(req(`id=${ID}`))).text();
    const b = await (await handler(new Request(`https://evil.example/api/share?id=${ID}`, { headers: { host: 'evil.example', 'x-forwarded-host': 'evil.example' } }))).text();
    expect(b).toBe(a);
    expect(b).not.toContain('evil.example');
  });

  it('uses SITE_URL for every absolute URL and for the template and fallback fetches', async () => {
    const site = 'https://cves.example.org';
    const f = fakeFetch({ [`${site}/index.html`]: html(), [rawUrl(ID)]: status(503), [`${site}/data/v1/cve/${shardOf(ID)}.json`]: json(shard) });
    const body = await (await createShareHandler({ fetch: f.fn, env: { SITE_URL: `${site}/`, VERCEL_PROJECT_PRODUCTION_URL: 'cverdict-psi.vercel.app' } })(req(`id=${ID}`))).text();
    expect(body).toContain(`<meta property="og:url" content="${site}/cve/${ID}" />`);
    expect(body).toContain(`${site}/og/exploited.png?v=`);
  });

  it('falls back to the own-domain copy on a raw 429, then prefers it for 10 minutes', async () => {
    const other = 'CVE-2026-101416';
    expect(shardOf(other)).not.toBe(shardOf(ID));
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: status(429), [ownUrl(ID)]: json(shard), [ownUrl(other)]: json(F.shardFile(F.WATCH)), [rawUrl(other)]: json(F.shardFile(F.WATCH)) });
    const handler = createShareHandler({ fetch: f.fn, env: {} });
    expect(await (await handler(req(`id=${ID}`))).text()).toContain('Exploited, score 100');
    expect(f.calls.slice(1).map((c) => c.url)).toEqual([rawUrl(ID), ownUrl(ID)]);
    expect(await (await handler(req(`id=${other}`))).text()).toContain('CVE-2026-101416: Watch, score 32');
    expect(f.count(rawUrl(other))).toBe(0);
    expect(f.count(ownUrl(other))).toBe(1);
    // After the breaker's 10 minutes (and the shard cache's 5), raw goes first again.
    vi.advanceTimersByTime(10 * 60_000 + 1);
    await handler(req(`id=${other}`));
    expect(f.count(rawUrl(other))).toBe(1);
  });

  it('does not spend an edge request on the fallback when raw says the shard is missing', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: status(404), [ownUrl(ID)]: json(shard) });
    const res = await createShareHandler({ fetch: f.fn, env: {} })(req(`id=${ID}`));
    expect(await res.text()).toBe(TEMPLATE);
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_SHORT);
    expect(f.count(ownUrl(ID))).toBe(0);
  });

  it('answers with the site card for a minute when both sources fail, and does not fetch that shard again meanwhile', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: status(503), [ownUrl(ID)]: status(500) });
    const handler = createShareHandler({ fetch: f.fn, env: {} });
    const res = await handler(req(`id=${ID}`));
    expect(await res.text()).toBe(TEMPLATE);
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_SHORT);
    const before = f.calls.length;
    vi.advanceTimersByTime(59_000);
    expect(await (await handler(req(`id=${ID}`))).text()).toBe(TEMPLATE);
    expect(f.calls.length).toBe(before);
    vi.advanceTimersByTime(2_000);
    await handler(req(`id=${ID}`));
    expect(f.calls.length).toBeGreaterThan(before);
  });

  it('ends at the one 1.5 s deadline shared by the template and shard fetches', async () => {
    // The template takes 1 s, the shard never answers: 1.5 s in all, not 2.5 s.
    const slowTemplate = () => new Promise<Response>((resolve) => setTimeout(() => resolve(html()()), 1000));
    const f = fakeFetch({ [TEMPLATE_URL]: slowTemplate, [rawUrl(ID)]: never, [ownUrl(ID)]: never });
    const handler = createShareHandler({ fetch: f.fn, env: {} });
    let done = false;
    const pending = handler(req(`id=${ID}`)).then((r) => {
      done = true;
      return r;
    });
    await vi.advanceTimersByTimeAsync(DEADLINE_MS - 1);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const res = await pending;
    expect(done).toBe(true);
    expect(await res.text()).toBe(TEMPLATE);
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_SHORT);
  });

  it('ends at the deadline even when a fetch ignores the abort signal', async () => {
    const deaf = (() => new Promise<Response>(() => {})) as typeof fetch;
    const handler = createShareHandler({ fetch: deaf, env: {} });
    const pending = handler(req(`id=${ID}`));
    await vi.advanceTimersByTimeAsync(DEADLINE_MS);
    const res = await pending;
    const body = await res.text();
    // No template either: the built-in stand-in page with the site card.
    expect(body).toContain('<!--share:start-->');
    expect(body).toContain(`${ORIGIN}/og/site.png?v=`);
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_SHORT);
  });

  it('cuts a shard at 2 MB of decompressed bytes, with or without a Content-Length', async () => {
    for (const headers of [{}, { 'content-length': '100' }] as Record<string, string>[]) {
      const big = stream(3 * 1024 * 1024, headers);
      let made: ReturnType<ReturnType<typeof stream>> | null = null;
      const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: () => (made = big()), [ownUrl(ID)]: status(500) });
      const res = await createShareHandler({ fetch: f.fn, env: {} })(req(`id=${ID}`));
      expect(await res.text()).toBe(TEMPLATE);
      expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_SHORT);
      expect(made!.sentBytes()).toBeLessThanOrEqual(SHARD_MAX_BYTES + 2 * 64 * 1024);
    }
  });

  it('caps the template at 64 KB and needs both markers in it', async () => {
    for (const page of [`${TEMPLATE}${' '.repeat(70 * 1024)}`, '<html><head><title>no markers</title></head></html>']) {
      const f = fakeFetch({ [TEMPLATE_URL]: html(page), [rawUrl(ID)]: json(shard) });
      const res = await createShareHandler({ fetch: f.fn, env: {} })(req(`id=${ID}`));
      const body = await res.text();
      expect(body).toContain('CVE-2026-109618: Exploited, score 100');
      expect(body).toContain('<p><a href="https://cverdict-psi.vercel.app/">CVErdict</a></p>');
      expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_SHORT);
    }
  });

  it('answers bad shard data with the site card', async () => {
    const cases: Record<string, Answer> = {
      'bad JSON': () => new Response('{"schema_version":1,'),
      'schema 2': json({ ...shard, schema_version: 2 }),
      'no generated_at': json({ ...shard, generated_at: 'soon' }),
      'items is a list': json({ ...shard, items: [] }),
      'wrong id inside': json({ ...shard, items: { [ID]: { ...F.EXPLOITED_KEV, id: 'CVE-2026-1' } } }),
    };
    for (const [name, answer] of Object.entries(cases)) {
      const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: answer });
      const res = await createShareHandler({ fetch: f.fn, env: {} })(req(`id=${ID}`));
      expect(await res.text(), name).toBe(TEMPLATE);
      expect(res.headers.get('vercel-cdn-cache-control'), name).toBe(CDN_CACHE_SHORT);
    }
  });

  it('reads a shard with a __proto__ key without polluting anything', async () => {
    const text = `{"schema_version":1,"generated_at":"${F.GENERATED_AT}","items":{"__proto__":{"polluted":true},"${ID}":${JSON.stringify(F.EXPLOITED_KEV)}}}`;
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: () => new Response(text) });
    const body = await (await createShareHandler({ fetch: f.fn, env: {} })(req(`id=${ID}`))).text();
    expect(body).toContain('Exploited, score 100');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('fetches a shard once for 100 requests, then revalidates it with its ETag after 5 minutes', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: [json(shard, { etag: '"v1"' }), () => new Response(null, { status: 304 })] });
    const handler = createShareHandler({ fetch: f.fn, env: {} });
    const bodies = await Promise.all(Array.from({ length: 100 }, () => handler(req(`id=${ID}`)).then((r) => r.text())));
    expect(new Set(bodies).size).toBe(1);
    for (let i = 0; i < 100; i++) await handler(req(`id=${ID}`));
    expect(f.count(rawUrl(ID))).toBe(1);
    expect(f.count(TEMPLATE_URL)).toBe(1);
    vi.advanceTimersByTime(5 * 60_000 + 1);
    const again = await (await handler(req(`id=${ID}`))).text();
    expect(again).toBe(bodies[0]);
    const calls = f.calls.filter((c) => c.url === rawUrl(ID));
    expect(calls).toHaveLength(2);
    expect(calls[1].headers['if-none-match']).toBe('"v1"');
  });

  it('keeps answering from the cached shard when a revalidation fails', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: html(), [rawUrl(ID)]: [json(shard), status(503)], [ownUrl(ID)]: status(503) });
    const handler = createShareHandler({ fetch: f.fn, env: {} });
    const first = await (await handler(req(`id=${ID}`))).text();
    vi.advanceTimersByTime(5 * 60_000 + 1);
    const res = await handler(req(`id=${ID}`));
    expect(await res.text()).toBe(first);
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_OK);
  });

  it('reloads the template after 10 minutes, and retries a failed one after a minute', async () => {
    const f = fakeFetch({ [TEMPLATE_URL]: [status(500), html()], [rawUrl(ID)]: json(shard) });
    const handler = createShareHandler({ fetch: f.fn, env: {} });
    expect(await (await handler(req(`id=${ID}`))).text()).toContain('<p><a href=');
    await handler(req(`id=${ID}`));
    expect(f.count(TEMPLATE_URL)).toBe(1);
    vi.advanceTimersByTime(60_001);
    expect(await (await handler(req(`id=${ID}`))).text()).toContain('<script type="module"');
    expect(f.count(TEMPLATE_URL)).toBe(2);
    vi.advanceTimersByTime(10 * 60_000 + 1);
    await handler(req(`id=${ID}`));
    expect(f.count(TEMPLATE_URL)).toBe(3);
  });
});

describe('vercel.json', () => {
  it('is the user-agent condition of vercel.json, whose bot rule sits after the data rewrites and before the catch-all', () => {
    const vercel = JSON.parse(readFileSync(new URL('../../vercel.json', import.meta.url), 'utf8')) as {
      rewrites: { source: string; destination: string; has?: { type: string; key: string; value: string }[] }[];
      functions: Record<string, { maxDuration: number }>;
    };
    const i = vercel.rewrites.findIndex((r) => r.destination === '/api/share?id=:id');
    expect(vercel.rewrites[i].source).toBe('/cve/:id([Cc][Vv][Ee]-[0-9]+-[0-9]+)');
    expect(vercel.rewrites[i].has).toEqual([{ type: 'header', key: 'user-agent', value: BOT_UA_VALUE }]);
    const data = vercel.rewrites.findIndex((r) => r.source.startsWith('/data/'));
    const feeds = vercel.rewrites.findIndex((r) => r.source.startsWith('/feeds/'));
    const all = vercel.rewrites.findIndex((r) => r.source === '/(.*)');
    expect(i).toBeGreaterThan(data);
    expect(i).toBeGreaterThan(feeds);
    expect(i).toBe(all - 1);
    expect(vercel.functions['api/share.ts'].maxDuration).toBe(10);
    expect(BOT_UA_TOKENS.length).toBe(new Set(BOT_UA_TOKENS).size);
  });
});
