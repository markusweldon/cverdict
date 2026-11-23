/**
 * Per-vendor and per-product feed URLs (`/feeds/v/<slug>.xml`, served by api/feed.ts). The feed is
 * a Vercel function, so a build for another host (GitHub Pages) links to the main site's feed.
 */
import { slugify } from '../../shared/slug';

/** Set by vite.config.ts: "" on Vercel (this origin serves the feeds), else BRAND.siteUrl. */
declare const __VENDOR_FEEDS_ORIGIN__: string | undefined;

export function vendorFeedOrigin(): string {
  const configured = typeof __VENDOR_FEEDS_ORIGIN__ === 'string' ? __VENDOR_FEEDS_ORIGIN__ : '';
  return configured || (typeof window !== 'undefined' ? window.location.origin : '');
}

/** The feed URL for a watched name, or null when the name has no ASCII letter or digit. */
export function vendorFeedUrl(name: string, origin: string = vendorFeedOrigin()): string | null {
  const slug = slugify(name);
  return slug ? `${origin.replace(/\/+$/, '')}/feeds/v/${slug}.xml` : null;
}
