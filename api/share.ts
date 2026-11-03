/**
 * Link previews for CVE pages, for link-preview bots only.
 *
 * vercel.json rewrites /cve/<id> to /api/share?id=<id> only when the user-agent is one of
 * BOT_UA_TOKENS (shared/share.ts); people get the static index.html and never reach this. The
 * response is the site's own index.html with the per-CVE title, description and Open Graph tags
 * between the share markers, built from the CVE's published detail shard.
 *
 * Bounded on purpose (docs/DEPLOY.md, "Link previews"): one 1.5 s deadline for every fetch of a
 * request, bodies capped by decompressed bytes, every shard text cached for raw's own 5 minutes
 * and then revalidated, a breaker that prefers the fallback for 10 minutes after raw fails, and
 * 60 seconds without fetching for a shard that both sources failed. Anything unexpected answers
 * with the static site card. No npm dependencies; imports use `.js` extensions (plain Node ESM).
 */
import { BRAND, RAW_DATA_URL, REPO_URL } from '../shared/brand.js';
import { CVE_ID_RE, shardOf } from '../shared/shard.js';
import { injectHead, minimalTemplate, notInDataHead, readShareRecord, SHARE_END, SHARE_START, shareHead, siteOrigin } from '../shared/share.js';

export const DEADLINE_MS = 1500;
export const SHARD_MAX_BYTES = 2 * 1024 * 1024;
export const TEMPLATE_MAX_BYTES = 64 * 1024;
const SHARD_FRESH_MS = 5 * 60_000;
const TEMPLATE_FRESH_MS = 10 * 60_000;
const TEMPLATE_RETRY_MS = 60_000;
const BREAKER_MS = 10 * 60_000;
const SHARD_RETRY_MS = 60_000;
const ID_MAX = 24;

/** CDN caching: 15 minutes, then stale copies while it revalidates, and for a week if the function fails. */
export const CDN_CACHE_OK = 'max-age=900, stale-while-revalidate=3600, stale-if-error=604800';
/** When the data could not be read, the generic answer is cached for a minute only. */
export const CDN_CACHE_SHORT = 'max-age=60';

interface Options {
  fetch?: typeof fetch;
  env?: Readonly<Record<string, string | undefined>>;
}

type Fetched = { ok: true; text: string; etag: string | null } | { ok: false; status: number | 'error' | 'too_big'; notModified?: boolean };

/** GET `url` and read at most `max` decompressed bytes; Content-Length is not trusted. */
async function fetchText(doFetch: typeof fetch, url: string, signal: AbortSignal, max: number, etag: string | null): Promise<Fetched> {
  let res: Response;
  try {
    const headers: Record<string, string> = { 'user-agent': `${BRAND.slug}-share (+${REPO_URL})` };
    if (etag) headers['if-none-match'] = etag;
    res = await doFetch(url, { signal, headers, redirect: 'error' });
  } catch {
    return { ok: false, status: 'error' };
  }
  if (res.status === 304) return { ok: false, status: 304, notModified: true };
  if (res.status !== 200 || !res.body) {
    void res.body?.cancel().catch(() => {});
    return { ok: false, status: res.status };
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) {
        void reader.cancel().catch(() => {});
        return { ok: false, status: 'too_big' };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, status: 'error' };
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    bytes.set(c, at);
    at += c.byteLength;
  }
  return { ok: true, text: new TextDecoder().decode(bytes), etag: res.headers.get('etag') };
}

/** Upstream trouble that the fallback may not share: rate limits, server errors, timeouts, network. */
const isOutage = (status: Fetched & { ok: false }) => status.status === 'error' || status.status === 429 || (typeof status.status === 'number' && status.status >= 500);

interface ShardEntry {
  text: string;
  etag: string | null;
  /** The URL the text came from: an ETag is only sent back to it. */
  from: string;
  at: number;
}

/** A request handler with its own caches. The deployed function is one of these. */
export function createShareHandler(options: Options = {}): (request: Request) => Promise<Response> {
  const doFetch = options.fetch ?? ((input, init) => fetch(input, init));
  const shards = new Map<string, ShardEntry>();
  const shardRetryAt = new Map<string, number>();
  const shardInflight = new Map<string, Promise<string | null>>();
  let rawDownUntil = 0;
  let template: { html: string; at: number } | null = null;
  let templateRetryAt = 0;
  let templateInflight: Promise<void> | null = null;

  /** The built index.html of the production domain; `fallback` when it could not be loaded. */
  async function loadTemplate(origin: string, signal: AbortSignal): Promise<{ html: string; fallback: boolean }> {
    const now = Date.now();
    if (template && now - template.at < TEMPLATE_FRESH_MS) return { html: template.html, fallback: false };
    if (now >= templateRetryAt) {
      templateInflight ??= (async () => {
        const got = await fetchText(doFetch, `${origin}/index.html`, signal, TEMPLATE_MAX_BYTES, null);
        if (got.ok && got.text.includes(SHARE_START) && got.text.includes(SHARE_END)) template = { html: got.text, at: Date.now() };
        else templateRetryAt = Date.now() + TEMPLATE_RETRY_MS;
      })().finally(() => {
        templateInflight = null;
      });
      await templateInflight;
    }
    // A stale copy beats the stand-in page; neither is worth caching for long.
    return template ? { html: template.html, fallback: Date.now() - template.at >= TEMPLATE_FRESH_MS } : { html: minimalTemplate(origin), fallback: true };
  }

  async function fetchShard(name: string, origin: string, signal: AbortSignal): Promise<string | null> {
    const raw = `${RAW_DATA_URL}/v1/cve/${name}.json`;
    const own = `${origin}/data/v1/cve/${name}.json`;
    const cached = shards.get(name);
    const order = Date.now() < rawDownUntil ? [own, raw] : [raw, own];
    for (const url of order) {
      const got = await fetchText(doFetch, url, signal, SHARD_MAX_BYTES, cached?.from === url ? cached.etag : null);
      if (got.ok) {
        shards.set(name, { text: got.text, etag: got.etag, from: url, at: Date.now() });
        return got.text;
      }
      if (got.notModified && cached) {
        cached.at = Date.now();
        return cached.text;
      }
      if (url !== raw) continue;
      // raw answered: only an outage of raw is worth an edge request to the own-domain copy.
      if (!isOutage(got)) break;
      rawDownUntil = Date.now() + BREAKER_MS;
    }
    shardRetryAt.set(name, Date.now() + SHARD_RETRY_MS);
    return cached?.text ?? null;
  }

  async function loadShard(name: string, origin: string, signal: AbortSignal): Promise<string | null> {
    const cached = shards.get(name);
    const now = Date.now();
    if (cached && now - cached.at < SHARD_FRESH_MS) return cached.text;
    if (now < (shardRetryAt.get(name) ?? 0)) return cached?.text ?? null;
    let p = shardInflight.get(name);
    if (!p) {
      p = fetchShard(name, origin, signal).finally(() => shardInflight.delete(name));
      shardInflight.set(name, p);
    }
    return p;
  }

  return async function handler(request: Request): Promise<Response> {
    const origin = siteOrigin(options.env ?? process.env);
    // One deadline for the whole request: every fetch shares its signal, and the answer is sent
    // when it passes even if a fetch ignored the signal.
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(new Error('deadline')), DEADLINE_MS);
    const late = new Promise<null>((resolve) => ctrl.signal.addEventListener('abort', () => resolve(null), { once: true }));
    const within = <T>(work: Promise<T>): Promise<T | null> => Promise.race([work, late]);
    let html = minimalTemplate(origin);
    let cdn = CDN_CACHE_SHORT;
    try {
      const ids = new URL(request.url).searchParams.getAll('id');
      const id = ids.length === 1 ? ids[0].trim().toUpperCase() : '';
      const valid = id.length <= ID_MAX && CVE_ID_RE.test(id);
      const [page, text] = await Promise.all([within(loadTemplate(origin, ctrl.signal)), valid ? within(loadShard(shardOf(id), origin, ctrl.signal)) : null]);
      if (page) html = page.html;
      const ok = page !== null && !page.fallback;
      if (!valid) {
        // Not exactly one well-formed ID: the site card, which depends on nothing upstream.
        if (ok) cdn = CDN_CACHE_OK;
      } else if (text !== null) {
        const shard: unknown = JSON.parse(text);
        if (typeof shard === 'object' && shard !== null && (shard as { schema_version?: unknown }).schema_version === 1) {
          const { generated_at: generatedAt, items } = shard as { generated_at?: unknown; items?: unknown };
          const record = typeof generatedAt === 'string' && Number.isFinite(Date.parse(generatedAt)) ? readShareRecord(items, id) : null;
          if (record === undefined) html = injectHead(html, notInDataHead(origin, id));
          else if (record) html = injectHead(html, shareHead({ origin, detail: record, generatedAt: generatedAt as string }));
          if (record !== null && ok) cdn = CDN_CACHE_OK;
        }
      }
    } catch {
      // Bad JSON or anything else: whatever page is in hand, with its static site card.
    } finally {
      clearTimeout(timer);
    }
    const headers = {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=300',
      'vercel-cdn-cache-control': cdn,
    };
    return new Response(request.method === 'HEAD' ? null : html, { status: 200, headers });
  };
}

const handler = createShareHandler();
export const GET = handler;
export const HEAD = handler;
