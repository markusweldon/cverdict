/**
 * Per-vendor and per-product Atom feeds: `/feeds/v/<slug>.xml` (vercel.json rewrites it to
 * /api/feed?v=<slug>). The events of v1/events.json whose vendor or product has that slug
 * (shared/slug.ts, the watchlist's rule), rendered with the same entries as feeds/events.xml.
 *
 * Not a proxy: the only upstream URL is the constant `${RAW_DATA_URL}/v1/events.json`; nothing
 * from the request reaches a URL or a header. Bounded like api/share.ts (docs/DEPLOY.md, "Vendor
 * feeds"): one 1.5 s deadline per request, a 1 MB decompressed cap, the text kept in memory and
 * revalidated by ETag after raw's own 5 minutes, the last good copy served when raw fails, and a
 * minute without fetching after a failure. One CDN copy per slug, kept until shortly after the next
 * hourly publish, so invocations grow with the number of slugs, not of subscribers.
 * No npm dependencies; imports use `.js` extensions (plain Node ESM).
 */
import { createHash } from 'node:crypto';
import { eventsFeed, selectFeedEvents } from '../shared/atom.js';
import { BRAND, RAW_DATA_URL, REPO_URL } from '../shared/brand.js';
import { EVENT_TYPES, TIERS, type EventItem } from '../shared/contract.js';
import { CVE_ID_RE } from '../shared/shard.js';
import { siteOrigin } from '../shared/share.js';
import { matchesSlug, SLUG_RE } from '../shared/slug.js';
import { fetchText } from './_http.js';

export const DEADLINE_MS = 1500;
export const EVENTS_MAX_BYTES = 1024 * 1024;
/** Entries per feed, and a hard stop on the body. */
export const FEED_MAX_ENTRIES = 50;
export const FEED_MAX_BYTES = 64 * 1024;
export const EVENTS_URL = `${RAW_DATA_URL}/v1/events.json`;
const FRESH_MS = 5 * 60_000;
const RETRY_MS = 60_000;
/** The next hourly publish is expected this long after generated_at. */
const NEXT_RUN_MS = 70 * 60_000;
export const TTL_MIN_S = 120;
export const TTL_MAX_S = 1800;
const UA = `${BRAND.slug}-feed (+${REPO_URL})`;

/**
 * A bad name is the same mistake every time: a 404, which Vercel's CDN caches (it does not cache a
 * 400 or a 503), for a day.
 */
export const CDN_CACHE_BAD = 'max-age=86400';
/** No data at all: a 503, which the CDN does not cache; the header only asks clients to wait. */
export const CDN_CACHE_DOWN = 'max-age=60';
/** How late an hourly publish may be before the feed stops waiting for it at the 120 s floor. */
const LATE_MS = 10 * 60_000;
const HOUR_MS = 3_600_000;

interface Options {
  fetch?: typeof fetch;
  env?: Readonly<Record<string, string | undefined>>;
}

interface Loaded {
  text: string;
  etag: string | null;
  at: number;
  generatedAt: string;
  days: number;
  items: EventItem[];
}

const str = (v: unknown): v is string => typeof v === 'string';

/** An events.json item with the fields a feed entry reads; anything else is skipped. */
function readItem(v: unknown): EventItem | null {
  if (typeof v !== 'object' || v === null) return null;
  const o = v as Record<string, unknown>;
  if (!str(o.id) || !str(o.at) || !Number.isFinite(Date.parse(o.at)) || !str(o.cve) || !CVE_ID_RE.test(o.cve)) return null;
  if (!(EVENT_TYPES as readonly unknown[]).includes(o.type) || !(TIERS as readonly unknown[]).includes(o.tier_after)) return null;
  if (!(o.tier_before === null || (TIERS as readonly unknown[]).includes(o.tier_before))) return null;
  if (!str(o.vendor) || !str(o.product) || !str(o.title) || !str(o.detail) || typeof o.score !== 'number' || !(o.url === null || str(o.url))) return null;
  return o as unknown as EventItem;
}

function parseEvents(text: string): Omit<Loaded, 'text' | 'etag' | 'at'> | null {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof doc !== 'object' || doc === null) return null;
  const d = doc as Record<string, unknown>;
  if (d.schema_version !== 1 || !str(d.generated_at) || !Number.isFinite(Date.parse(d.generated_at)) || !Array.isArray(d.items)) return null;
  const items = d.items.map(readItem).filter((i): i is EventItem => i !== null);
  return { generatedAt: d.generated_at, days: Number.isInteger(d.days) ? (d.days as number) : 7, items };
}

/**
 * Seconds the CDN keeps a feed: until shortly after the next hourly publish, within
 * TTL_MIN_S..TTL_MAX_S. When the expected publish is more than LATE_MS overdue (an hour with no
 * change publishes nothing, so generated_at stays old), it waits for the same minute of the next hour.
 */
export function cdnTtl(generatedAt: string, now: number): number {
  let ms = Date.parse(generatedAt) + NEXT_RUN_MS - now;
  if (!Number.isFinite(ms)) return TTL_MIN_S;
  if (ms < -LATE_MS) ms = ((ms % HOUR_MS) + HOUR_MS) % HOUR_MS;
  return Math.min(TTL_MAX_S, Math.max(TTL_MIN_S, Math.round(ms / 1000)));
}

/** The feed for one slug, entries dropped from the oldest end until it fits FEED_MAX_BYTES. */
export function renderSlugFeed(slug: string, data: Pick<Loaded, 'generatedAt' | 'days' | 'items'>, origin: string): string {
  let items = selectFeedEvents(
    data.items.filter((it) => matchesSlug(slug, it)),
    FEED_MAX_ENTRIES,
  );
  for (;;) {
    const xml = eventsFeed({
      siteUrl: origin,
      idBase: BRAND.feedIdBase,
      path: `feeds/v/${slug}.xml`,
      title: `${BRAND.name} · verdict events for ${slug}`,
      subtitle: items.length
        ? `Why verdicts moved in the last ${data.days} days for vendor or product "${slug}". Newest first, up to ${FEED_MAX_ENTRIES}.`
        : `No events for ${slug} in the last ${data.days} days.`,
      alternate: '',
      fallbackUpdated: new Date(Date.parse(data.generatedAt)).toISOString(),
      items,
    });
    if (Buffer.byteLength(xml, 'utf8') <= FEED_MAX_BYTES || items.length === 0) return xml;
    items = items.slice(0, Math.max(0, Math.floor(items.length * 0.8)));
  }
}

const etagOf = (body: string) => `"${createHash('sha256').update(body).digest('base64url').slice(0, 27)}"`;

/** True when an If-None-Match header names `etag` (or is `*`). Weak and strong compare the same. */
function matchesEtag(header: string | null, etag: string): boolean {
  if (!header) return false;
  return header.split(',').some((t) => {
    const v = t.trim().replace(/^W\//, '');
    return v === '*' || v === etag;
  });
}

/** A request handler with its own cache. The deployed function is one of these. */
export function createFeedHandler(options: Options = {}): (request: Request) => Promise<Response> {
  const doFetch = options.fetch ?? ((input, init) => fetch(input, init));
  let cached: Loaded | null = null;
  let retryAt = 0;
  let inflight: Promise<void> | null = null;

  async function refresh(signal: AbortSignal): Promise<void> {
    const got = await fetchText(doFetch, EVENTS_URL, signal, EVENTS_MAX_BYTES, cached?.etag ?? null, UA);
    if (got.ok) {
      const parsed = parseEvents(got.text);
      if (parsed) {
        cached = { ...parsed, text: got.text, etag: got.etag, at: Date.now() };
        return;
      }
    } else if (got.notModified && cached) {
      cached.at = Date.now();
      return;
    }
    retryAt = Date.now() + RETRY_MS;
  }

  async function load(signal: AbortSignal): Promise<Loaded | null> {
    const now = Date.now();
    if (cached && now - cached.at < FRESH_MS) return cached;
    if (now >= retryAt) {
      inflight ??= refresh(signal).finally(() => {
        inflight = null;
      });
      await inflight;
    }
    return cached;
  }

  return async function handler(request: Request): Promise<Response> {
    const head = request.method === 'HEAD';
    const text = (status: number, body: string, cdn: string, extra: Record<string, string> = {}) =>
      new Response(head ? null : body, { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': `public, max-age=${status === 404 ? 3600 : 60}`, 'vercel-cdn-cache-control': cdn, ...extra } });

    const values = new URL(request.url).searchParams.getAll('v');
    const slug = values.length === 1 ? values[0] : '';
    if (!SLUG_RE.test(slug)) return text(404, 'Not a feed name. Use lower-case letters, digits and hyphens, as in /feeds/v/fortinet.xml.\n', CDN_CACHE_BAD);

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(new Error('deadline')), DEADLINE_MS);
    const late = new Promise<null>((resolve) => ctrl.signal.addEventListener('abort', () => resolve(null), { once: true }));
    let data: Loaded | null;
    try {
      data = await Promise.race([load(ctrl.signal), late]);
      // The deadline passed while a fetch ignored the signal: a copy in hand still beats nothing.
      data ??= cached;
    } finally {
      clearTimeout(timer);
    }
    if (!data) return text(503, 'The event data could not be read. Try again in a few minutes.\n', CDN_CACHE_DOWN, { 'retry-after': '300' });

    const body = renderSlugFeed(slug, data, siteOrigin(options.env ?? process.env));
    const etag = etagOf(body);
    const headers = {
      'content-type': 'application/atom+xml; charset=utf-8',
      'cache-control': 'public, max-age=300',
      'vercel-cdn-cache-control': `max-age=${cdnTtl(data.generatedAt, Date.now())}, stale-while-revalidate=600, stale-if-error=86400`,
      etag,
    };
    if (matchesEtag(request.headers.get('if-none-match'), etag)) return new Response(null, { status: 304, headers });
    return new Response(head ? null : body, { status: 200, headers });
  };
}

const handler = createFeedHandler();
export const GET = handler;
export const HEAD = handler;
