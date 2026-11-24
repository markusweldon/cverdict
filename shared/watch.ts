/**
 * The watchlist's match rule: a name matches a CVE when it equals the CVE's vendor or its product,
 * case-insensitive, with runs of whitespace as one space. The site's watchlist (site/src/state.ts)
 * and the MCP server's check_inventory and changes_since (mcp/src/tools.ts) both use it, so a name
 * that lights up a row on the site matches the same CVEs for an agent.
 *
 * Pure, no imports, so the site, the MCP bundle and the api functions can all use it.
 */

/** Longest name the watchlist keeps. */
export const WATCH_NAME_MAX = 80;

export const normalizeName = (s: string): string => s.trim().toLowerCase().replace(/\s+/g, ' ');

/** True when a normalized name in `list` equals the vendor or the product. */
export function matchesName(list: readonly string[], vendor: string, product: string): boolean {
  if (list.length === 0) return false;
  return (vendor !== '' && list.includes(normalizeName(vendor))) || (product !== '' && list.includes(normalizeName(product)));
}

/** matchesName for a Row (`v` vendor, `p` product). */
export const isWatched = (list: readonly string[], row: { v: string; p: string }): boolean => matchesName(list, row.v, row.p);
