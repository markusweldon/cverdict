import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BRAND } from '../../shared/brand';
import type { EventItem, EventsFile } from '../../shared/contract';
import { SLUG_RE, slugify } from '../../shared/slug';
import { CDN_CACHE_BAD, CDN_CACHE_DOWN, DEADLINE_MS, EVENTS_MAX_BYTES, EVENTS_URL, FEED_MAX_BYTES, FEED_MAX_ENTRIES, GET, HEAD, TTL_MAX_S, TTL_MIN_S, cdnTtl, createFeedHandler } from '../feed';

const ORIGIN = 'https://cverdict.dev';
const NOW = new Date('2026-11-23T17:00:00Z');
const GENERATED = '2026-11-23T16:47:29.170Z';

type Answer = Response | Promise<Response> | (() => Response | Promise<Response>);
interface Call {
  url: string;
  init: RequestInit | undefined;
}

/** A fetch that answers from `routes` in order and records every call. Unknown URLs get a 404. */
function fakeFetch(routes: Record<string, Answer[]>) {
  const calls: Call[] = [];
  const fn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const list = routes[url];
    const route = list ? (list.length > 1 ? list.shift()! : list[0]) : undefined;
    if (!route) return new Response('not found', { status: 404 });
    const res = typeof route === 'function' ? route() : route;
    return await new Promise<Response>((resolve, reject) => {
      const signal = init?.signal;
      if (signal?.aborted) return reject(signal.reason);
      signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
      Promise.resolve(res).then(resolve, reject);
    });
  }) as typeof fetch;
  return { fn, calls };
}

let seq = 0;
function ev(o: Partial<EventItem> = {}): EventItem {
  const cve = o.cve ?? `CVE-2026-${100000 + seq++}`;
  const type = o.type ?? 'tier_up';
  const tier = o.tier_after ?? 'likely';
  return {
    id: type === 'tier_up' ? `tier_up:${cve}:${tier}` : `${type}:${cve}`,
    at: '2026-11-23T16:47:29Z',
    type,
    cve,
    vendor: 'Fortinet',
    product: 'FortiOS',
    tier_before: 'watch',
    tier_after: tier,
    score: 61,
    title: `${cve} · Fortinet FortiOS · now Likely next`,
    via: 'computed',
    url: null,
    detail: 'Rose from Watch to Likely next.',
    backfill: false,
    ...o,
  };
}

function file(items: EventItem[], o: Partial<EventsFile> = {}): EventsFile {
  return { schema_version: 1, generated_at: GENERATED, previous_at: null, days: 7, max_items: 1000, catalogs: { kev: null, eu_kev: null }, items, ...o };
}

const json = (value: unknown, headers: Record<string, string> = {}) => () => new Response(JSON.stringify(value), { headers: { 'content-type': 'text/plain; charset=utf-8', ...headers } });
const status = (code: number) => () => new Response('error', { status: code });
const never = () => new Promise<Response>(() => {});
const req = (query: string, init?: RequestInit) => new Request(`${ORIGIN}/api/feed?${query}`, init);
const handlerWith = (routes: Record<string, Answer[]>, env: Record<string, string> = { SITE_URL: ORIGIN }) => {
  const f = fakeFetch(routes);
  return { h: createFeedHandler({ fetch: f.fn, env }), calls: f.calls };
};

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe('api/feed', () => {
  it('serves the events whose vendor or product has the slug, as Atom with shared caching', async () => {
    const items = [
      ev({ cve: 'CVE-2026-1001', vendor: 'Fortinet', product: 'FortiOS' }),
      ev({ cve: 'CVE-2026-1002', vendor: 'Acme', product: 'Fortinet' }),
      ev({ cve: 'CVE-2026-1003', vendor: 'Fortinet Inc.', product: 'FortiGate' }),
      ev({ cve: 'CVE-2026-1004', vendor: 'Ivanti', product: 'Connect Secure' }),
    ];
    const { h, calls } = handlerWith({ [EVENTS_URL]: [json(file(items), { etag: '"e1"' })] });
    const res = await h(req('v=fortinet'));
    const body = await res.text();
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('application/atom+xml; charset=utf-8');
    expect(res.headers.get('cache-control')).toBe('public, max-age=300');
    // Next publish expected at 17:57:29; it is 17:00:00.
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(`max-age=${TTL_MAX_S}, stale-while-revalidate=600, stale-if-error=86400`);
    expect(res.headers.get('etag')).toMatch(/^"[A-Za-z0-9_-]{27}"$/);
    expect(body.match(/<entry>/g)).toHaveLength(2);
    expect(body).toContain('CVE-2026-1001');
    expect(body).toContain('CVE-2026-1002');
    expect(body).not.toContain('CVE-2026-1003');
    expect(body).toContain(`<link rel="self" type="application/atom+xml" href="${ORIGIN}/feeds/v/fortinet.xml"/>`);
    expect(body).toContain(`<id>${BRAND.feedIdBase}/feeds/v/fortinet.xml</id>`);
    expect(body).toContain('<id>tag:cverdict-psi.vercel.app,2026:cverdict/event/tier_up:CVE-2026-1001:likely</id>');
    expect(calls.map((c) => c.url)).toEqual([EVENTS_URL]);
    expect(calls[0].init?.redirect).toBe('error');
    expect(slugify('Fortinet Inc.')).toBe('fortinet-inc');
    const other = await h(req('v=fortinet-inc'));
    expect((await other.text()).match(/<entry>/g)).toHaveLength(1);
  });

  it('answers 304 to a client that already has this version', async () => {
    const { h } = handlerWith({ [EVENTS_URL]: [json(file([ev()]))] });
    const first = await h(req('v=fortios'));
    const etag = first.headers.get('etag')!;
    const again = await h(req('v=fortios', { headers: { 'if-none-match': `W/${etag}` } }));
    expect(again.status).toBe(304);
    expect(await again.text()).toBe('');
    expect(again.headers.get('etag')).toBe(etag);
    expect((await h(req('v=fortios', { headers: { 'if-none-match': '"other"' } }))).status).toBe(200);
  });

  it('gives a valid empty feed for a name with no events, not a 404', async () => {
    const { h } = handlerWith({ [EVENTS_URL]: [json(file([ev()]))] });
    const res = await h(req('v=nobody'));
    const body = await res.text();
    expect(res.status).toBe(200);
    expect(body).toContain('<subtitle type="text">No events for nobody in the last 7 days.</subtitle>');
    expect(body).toContain(`<updated>${GENERATED}</updated>`);
    expect(body).not.toContain('<entry>');
  });

  it.each([
    ['', 'missing'],
    ['v=', 'empty'],
    ['v=Fortinet', 'upper case'],
    ['v=..%2Fetc', 'path'],
    ['v=a%2Fb', 'slash'],
    ['v=-fortinet', 'leading hyphen'],
    ['v=fortinet-', 'trailing hyphen'],
    ['v=fort inet', 'space'],
    ['v=f%C3%B6rtinet', 'non-ASCII'],
    [`v=${'a'.repeat(65)}`, 'too long'],
    ['v=a&v=b', 'two names'],
    ['v=https://evil.example/x', 'a URL'],
    ['v=%00', 'NUL'],
  ])('rejects %j (%s) with a 404 the CDN keeps for a day, without fetching', async (query) => {
    const { h, calls } = handlerWith({ [EVENTS_URL]: [json(file([ev()]))] });
    const res = await h(req(query));
    expect(res.status).toBe(404);
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_BAD);
    expect(res.headers.get('cache-control')).toBe('public, max-age=3600');
    expect(res.headers.get('content-type')).toBe('text/plain; charset=utf-8');
    expect(calls).toHaveLength(0);
  });

  it('accepts exactly the slugs the site makes', () => {
    for (const name of ['Fortinet', 'Palo Alto Networks', 'F5', 'Citrix NetScaler ADC', 'Microsoft Windows Server 2025', 'Zyxel', 'Ivanti Connect Secure', 'Schneider Électric', 'x'.repeat(200)]) {
      expect(SLUG_RE.test(slugify(name))).toBe(true);
    }
    expect(slugify('日本語')).toBe('');
    expect(slugify('  --A/B  ')).toBe('a-b');
  });

  it('never proxies: request headers and query do not change the upstream URL, its headers or the links', async () => {
    const { h, calls } = handlerWith({ [EVENTS_URL]: [json(file([ev()]))] }, {});
    const res = await h(
      req('v=fortinet&url=https://evil.example&host=evil.example', {
        headers: { host: 'evil.example', 'x-forwarded-host': 'evil.example', cookie: 'a=b', authorization: 'Bearer x', 'if-none-match': '"x"' },
      }),
    );
    const body = await res.text();
    expect(calls.map((c) => c.url)).toEqual([EVENTS_URL]);
    const sent = calls[0].init?.headers as Record<string, string>;
    expect(Object.keys(sent).sort()).toEqual(['user-agent']);
    expect(body).not.toContain('evil.example');
    // Without SITE_URL the links use the production site, never the request's host.
    expect(body).toContain(`${BRAND.siteUrl}/feeds/v/fortinet.xml`);
  });

  it('keeps every urgent event and caps the entries and the bytes', async () => {
    const items = [
      ...Array.from({ length: 70 }, (_, i) => ev({ cve: `CVE-2026-${2000 + i}`, at: new Date(NOW.getTime() - i * 60_000).toISOString().replace('.000Z', 'Z') })),
      ev({ cve: 'CVE-2026-9999', type: 'kev_added', tier_after: 'exploited', via: 'kev', at: '2026-11-18T00:00:00Z' }),
    ];
    const { h } = handlerWith({ [EVENTS_URL]: [json(file(items))] });
    const body = await (await h(req('v=fortinet'))).text();
    expect(body.match(/<entry>/g)).toHaveLength(FEED_MAX_ENTRIES);
    expect(body).toContain('kev_added:CVE-2026-9999');

    const huge = Array.from({ length: 60 }, (_, i) => ev({ cve: `CVE-2026-${3000 + i}`, detail: 'x'.repeat(4000) }));
    const big = handlerWith({ [EVENTS_URL]: [json(file(huge))] });
    const bigBody = await (await big.h(req('v=fortinet'))).text();
    expect(Buffer.byteLength(bigBody)).toBeLessThanOrEqual(FEED_MAX_BYTES);
    expect(bigBody.match(/<entry>/g)!.length).toBeGreaterThan(5);
    expect(bigBody.trimEnd().endsWith('</feed>')).toBe(true);
  });

  it('escapes hostile event text and skips malformed items', async () => {
    const bad = [ev({ title: '<script>alert(1)</script>', detail: ']]><x/>&' }), { ...ev(), cve: '../../etc' }, { ...ev(), type: 'nope' }, null, 'x'];
    const { h } = handlerWith({ [EVENTS_URL]: [json(file(bad as EventItem[]))] });
    const body = await (await h(req('v=fortinet'))).text();
    expect(body.match(/<entry>/g)).toHaveLength(1);
    expect(body).not.toContain('<script>');
    expect(body).toContain('&lt;script&gt;');
    expect(body).not.toContain('etc');
  });

  it('revalidates after five minutes with the ETag, and serves the last good copy while raw is down', async () => {
    const { h, calls } = handlerWith({ [EVENTS_URL]: [json(file([ev({ cve: 'CVE-2026-0001' })]), { etag: '"v1"' }), () => new Response(null, { status: 304 }), status(503)] });
    expect((await h(req('v=fortinet'))).status).toBe(200);
    await h(req('v=fortinet'));
    expect(calls).toHaveLength(1);
    vi.setSystemTime(new Date(NOW.getTime() + 6 * 60_000));
    const second = await h(req('v=fortinet'));
    expect(second.status).toBe(200);
    expect((calls[1].init?.headers as Record<string, string>)['if-none-match']).toBe('"v1"');
    vi.setSystemTime(new Date(NOW.getTime() + 12 * 60_000));
    const stale = await h(req('v=fortinet'));
    expect(stale.status).toBe(200);
    expect(await stale.text()).toContain('CVE-2026-0001');
    // After a failure it waits a minute before asking raw again.
    await h(req('v=fortinet'));
    expect(calls).toHaveLength(3);
  });

  it('answers 503 with Retry-After when there is no data at all', async () => {
    const { h } = handlerWith({ [EVENTS_URL]: [status(500)] });
    const res = await h(req('v=fortinet'));
    expect(res.status).toBe(503);
    expect(res.headers.get('retry-after')).toBe('300');
    expect(res.headers.get('vercel-cdn-cache-control')).toBe(CDN_CACHE_DOWN);
    const wrong = handlerWith({ [EVENTS_URL]: [json({ schema_version: 2, items: [] })] });
    expect((await wrong.h(req('v=fortinet'))).status).toBe(503);
  });

  it('gives up on raw at the deadline', async () => {
    const { h } = handlerWith({ [EVENTS_URL]: [never] });
    const pending = h(req('v=fortinet'));
    await vi.advanceTimersByTimeAsync(DEADLINE_MS + 1);
    expect((await pending).status).toBe(503);
  });

  it('refuses a body over the cap, whatever Content-Length says', async () => {
    const chunk = new Uint8Array(64 * 1024).fill(0x20);
    let sent = 0;
    const body = () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull(c) {
            if (sent > EVENTS_MAX_BYTES * 2) return c.close();
            sent += chunk.byteLength;
            c.enqueue(chunk);
          },
        }),
        { headers: { 'content-length': '10' } },
      );
    const { h } = handlerWith({ [EVENTS_URL]: [body] });
    expect((await h(req('v=fortinet'))).status).toBe(503);
    expect(sent).toBeLessThanOrEqual(EVENTS_MAX_BYTES + 2 * chunk.byteLength);
  });

  it('answers HEAD without a body', async () => {
    const { h } = handlerWith({ [EVENTS_URL]: [json(file([ev()]))] });
    const res = await h(req('v=fortinet', { method: 'HEAD' }));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('');
    expect(HEAD).toBe(GET);
  });

  it('keeps one CDN copy until shortly after the next hourly publish', () => {
    const gen = Date.parse(GENERATED);
    expect(cdnTtl(GENERATED, gen)).toBe(TTL_MAX_S);
    expect(cdnTtl(GENERATED, gen + 65 * 60_000)).toBe(300);
    expect(cdnTtl(GENERATED, gen + 69 * 60_000)).toBe(TTL_MIN_S);
    // A publish up to 10 minutes late is waited for at the floor.
    expect(cdnTtl(GENERATED, gen + 75 * 60_000)).toBe(TTL_MIN_S);
    // Later than that (an hour without changes publishes nothing): the same minute of the next hour.
    expect(cdnTtl(GENERATED, gen + 85 * 60_000)).toBe(TTL_MAX_S);
    expect(cdnTtl(GENERATED, gen + 5 * 3_600_000)).toBe(600);
    expect(cdnTtl(GENERATED, gen + 5 * 3_600_000 + 9 * 60_000)).toBe(TTL_MIN_S);
    expect(cdnTtl('nonsense', gen)).toBe(TTL_MIN_S);
  });
});

describe('vercel.json routes for vendor feeds', () => {
  interface Rule {
    source: string;
    destination?: string;
    missing?: unknown[];
    headers?: { key: string; value: string }[];
  }
  const vercel = JSON.parse(readFileSync(new URL('../../vercel.json', import.meta.url), 'utf8')) as { rewrites: Rule[]; headers: Rule[]; functions: Record<string, { maxDuration: number }> };
  /** The anchored RegExp of a Vercel source with only regex groups and one named parameter (no path-to-regexp in this repo). */
  const toRegExp = (source: string) => new RegExp(`^${source.replace(/:[a-z]+\(/g, '(')}$`);
  const rule = vercel.rewrites.find((r) => r.destination === '/api/feed?v=:slug')!;

  it('rewrites exactly the slugs the function accepts, before the static feed rule, and never a query that sets v', () => {
    const re = toRegExp(rule.source);
    for (const slug of ['fortinet', 'palo-alto-networks', 'f5', 'a', 'x'.repeat(64)]) {
      expect(re.test(`/feeds/v/${slug}.xml`)).toBe(true);
      expect(SLUG_RE.test(slug)).toBe(true);
    }
    for (const slug of ['Fortinet', '-a', 'a-', 'a/b', 'x'.repeat(65), '', 'a.b']) {
      expect(re.test(`/feeds/v/${slug}.xml`)).toBe(false);
      expect(SLUG_RE.test(slug)).toBe(false);
    }
    expect(rule.missing).toEqual([{ type: 'query', key: 'v' }]);
    const at = vercel.rewrites.indexOf(rule);
    const file = vercel.rewrites.findIndex((r) => r.source.startsWith('/feeds/:file'));
    expect(at).toBeLessThan(file);
    expect(toRegExp(vercel.rewrites[file].source).test('/feeds/v/fortinet.xml')).toBe(false);
    expect(vercel.functions['api/feed.ts'].maxDuration).toBe(10);
  });

  it('sends every other /feeds/v/ path to the function too, which answers a cacheable 404, never the SPA', () => {
    const at = vercel.rewrites.indexOf(rule);
    const rest = vercel.rewrites.findIndex((r) => r.source === '/feeds/v/(.*)');
    expect(rest).toBe(at + 1);
    expect(vercel.rewrites[rest].destination).toBe('/api/feed?v=');
    expect(rest).toBeLessThan(vercel.rewrites.findIndex((r) => r.source === '/(.*)'));
  });

  it('sets no Cache-Control on the function: its own CDN headers stand', () => {
    const caching = vercel.headers.filter((h) => h.headers?.some((x) => x.key.toLowerCase() === 'cache-control'));
    expect(caching.length).toBeGreaterThan(0);
    for (const h of caching) expect(toRegExp(h.source).test('/feeds/v/fortinet.xml')).toBe(false);
    expect(caching.some((h) => toRegExp(h.source).test('/feeds/events.xml'))).toBe(true);
    expect(caching.some((h) => toRegExp(h.source).test('/data/v1/events.json'))).toBe(true);
  });
});
