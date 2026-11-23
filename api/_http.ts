/**
 * Bounded GETs for the functions (api/share.ts, api/feed.ts): redirects are errors, the body is
 * read up to a byte cap counted after decompression (Content-Length is not trusted), and an ETag
 * can be sent back. Never throws. No npm dependencies; the underscore keeps Vercel from treating
 * this file as a function of its own.
 */
export type Fetched = { ok: true; text: string; etag: string | null } | { ok: false; status: number | 'error' | 'too_big'; notModified?: boolean };

/** GET `url` and read at most `max` decompressed bytes; Content-Length is not trusted. */
export async function fetchText(doFetch: typeof fetch, url: string, signal: AbortSignal, max: number, etag: string | null, userAgent: string): Promise<Fetched> {
  let res: Response;
  try {
    const headers: Record<string, string> = { 'user-agent': userAgent };
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
export const isOutage = (status: Fetched & { ok: false }) => status.status === 'error' || status.status === 429 || (typeof status.status === 'number' && status.status >= 500);

