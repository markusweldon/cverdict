/**
 * Slugs for per-vendor and per-product feeds (`/feeds/v/<slug>.xml`). The site, the feed function
 * and the docs all derive a slug from a name the same way, so a watched name and an event's vendor
 * or product meet on one key.
 *
 * Pure, no dependencies; imports carry `.js` extensions because api/feed.ts runs as plain Node ESM.
 */

export const SLUG_MAX = 64;
/** A valid slug: lower-case ASCII letters and digits in runs joined by single hyphens. */
export const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

/**
 * Slug of a vendor or product name: NFKD, accents dropped, lower case, every run of other
 * characters becomes one hyphen, no hyphen at either end, at most SLUG_MAX characters. "" when
 * nothing is left (a name with no ASCII letters or digits).
 */
export function slugify(name: string): string {
  const s = name
    .normalize('NFKD')
    .replace(/\p{M}+/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return s.slice(0, SLUG_MAX).replace(/-+$/, '');
}

/**
 * An event (or row) belongs to a slug's feed when its vendor or its product has that slug. Looser
 * than the watchlist's exact match (shared/watch.ts): case, accents and punctuation fold, so a feed
 * can carry spellings a watched name does not match ("Umbraco CMS" and "Umbraco-CMS"), and two
 * names can share one feed.
 */
export function matchesSlug(slug: string, item: { vendor: string; product: string }): boolean {
  return slug !== '' && (slugify(item.vendor) === slug || slugify(item.product) === slug);
}
