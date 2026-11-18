/**
 * Known-exploited catalogs besides CISA KEV, each a chip (shared/model.ts):
 *
 *   eu-kev      ENISA EU KEV, from the EUVD consolidated KEV dump. ENISA material, reproduction
 *               authorised with acknowledgement of the source.
 *   circl-kev   CIRCL's own catalog in Vulnerability-Lookup (CC0-1.0).
 *   siberkapan  SiberKapan's honeypot catalog in Vulnerability-Lookup (CC-BY-4.0).
 *
 * The CIRCL catalogs are GCVE BCP-07 entries. Only `exploited: true` entries with status
 * `confirmed` or `suspected` and a CVE ID are kept; the listing date is `asserted_at` ("mirrors
 * date added in KEV lists"), never `first_seen_at`, which BCP-07 allows to be estimated and changed
 * later. Each catalog is fetched through the cached source machinery: a failure serves the last good
 * copy (stale) or nothing, and never stops a run.
 */
import { CIRCL_KEV, EU_KEV, SIBERKAPAN, type SanityLimits } from '../config';
import type { CatalogId, CatalogListing, KevCatalog } from '../types';
import { normalizeYmd } from '../util/dates';
import type { HttpClient, Parsed } from '../util/http';
import { asArray, asNumber, asObject, asString, parseJson } from '../util/json';
import { normalizeCveId } from '../util/text';
import { requireAtLeast, SanityError, statusFromFetch, type SourceResult } from './source';

const EUVD_ID_RE = /^EUVD-\d{4}-\d{1,9}$/;

// ── ENISA EU KEV ───────────────────────────────────────────────────────────────────────────

/** An EU KEV row of the EUVD dump, before its date is checked against CISA KEV. */
export interface EuKevRaw {
  euvdId: string | null;
  /** The dump's `dateAdded`: the earliest date across CISA KEV and EU KEV. */
  dateAdded: string | null;
  /** True when CISA KEV is not among the row's sources. */
  euOnly: boolean;
}

/** Index the EU KEV rows of the dump by CVE ID (rows without `eukev_kev` are CISA's and skipped). */
export function parseEuKevDump(doc: unknown): { entries: Map<string, EuKevRaw>; rows: number; newest: string | null } {
  if (!Array.isArray(doc)) throw new Error('EUVD KEV dump: expected an array');
  const entries = new Map<string, EuKevRaw>();
  let rows = 0;
  let newest: string | null = null;
  for (const item of doc) {
    const o = asObject(item);
    const id = normalizeCveId(o?.cveId);
    if (!o || !id) continue;
    rows++;
    const sources = asArray(o.sources).filter((s): s is string => typeof s === 'string');
    if (!sources.includes('eukev_kev') || entries.has(id)) continue;
    const euvd = asString(o.euvdId)?.trim() ?? '';
    const dateAdded = normalizeYmd(o.dateAdded);
    const euOnly = !sources.includes('cisa_kev');
    if (dateAdded && euOnly && (!newest || dateAdded > newest)) newest = dateAdded;
    entries.set(id, { euvdId: EUVD_ID_RE.test(euvd) ? euvd : null, dateAdded, euOnly });
  }
  return { entries, rows, newest };
}

export function parseEuKevBody(body: Buffer, limits: SanityLimits): Parsed<Map<string, EuKevRaw>> {
  const { entries, rows, newest } = parseEuKevDump(parseJson(body, 'EUVD KEV dump'));
  requireAtLeast(rows, limits.euvdDumpRows, 'EUVD KEV dump rows');
  requireAtLeast(entries.size, limits.euKevEntries, 'EU KEV entries');
  return { value: entries, records: entries.size, version: newest };
}

export async function loadEuKev(http: HttpClient, limits: SanityLimits, signal?: AbortSignal): Promise<SourceResult<Map<string, EuKevRaw>>> {
  const fetched = await http.getSource({
    key: 'eu-kev',
    ext: 'json',
    urls: EU_KEV.urls,
    parse: (body) => parseEuKevBody(body, limits),
    minIntervalMs: EU_KEV.minIntervalMs,
    signal,
  });
  return { data: fetched.value, status: statusFromFetch(EU_KEV.info, fetched) };
}

/**
 * EU KEV listings with the dates the dump can vouch for. The dump gives one date, the earliest
 * across CISA KEV and EU KEV: it is EU KEV's own date for an EU-only row, and for a row in both
 * when it is before the CVE's CISA `dateAdded` (then it cannot be CISA's). Otherwise EU KEV listed
 * it on the CISA day or later, on a day the dump does not give: the listing is undated, with the
 * CISA date as `notBefore`.
 */
export function euKevListings(raw: ReadonlyMap<string, EuKevRaw>, kev: KevCatalog | null): Map<string, CatalogListing> {
  const out = new Map<string, CatalogListing>();
  for (const [id, e] of raw) {
    const cisa = kev?.entries.get(id)?.dateAdded;
    const added = e.dateAdded && (e.euOnly || (cisa !== undefined && e.dateAdded < cisa)) ? e.dateAdded : null;
    const listing: CatalogListing = { catalog: 'eu-kev', added, status: 'confirmed', url: e.euvdId ? EU_KEV.entryUrl(e.euvdId) : EU_KEV.info.home };
    if (added === null && !e.euOnly && cisa !== undefined && e.dateAdded && e.dateAdded >= cisa) listing.notBefore = cisa;
    out.set(id, listing);
  }
  return out;
}

// ── CIRCL Vulnerability-Lookup catalogs ────────────────────────────────────────────────────

interface CirclCatalog {
  id: CatalogId;
  /** `gcve.origin_uuid` of the catalog's entries. */
  origin: string;
  entryUrl: (cve: string) => string;
}

/** BCP-07 evidence signals that report exploitation that worked, not just attempts at it. */
const SUCCESS_SIGNALS = new Set(['successful_exploitation', 'confirmed_compromise']);

/**
 * True when an entry's evidence is all attempts: at least one evidence item, none with a signal of
 * successful exploitation or confirmed compromise. An entry with no evidence is CIRCL's bare
 * assertion and is not attempts-only.
 */
export function attemptsOnly(evidence: unknown): boolean {
  const items = asArray(evidence).map(asObject).filter((o): o is Record<string, unknown> => o !== null);
  return items.length > 0 && !items.some((o) => SUCCESS_SIGNALS.has(asString(o.signal) ?? ''));
}

/** Confirmed exploitation beats confirmed attempts, which beat suspected. */
const rank = (l: CatalogListing) => (l.status !== 'confirmed' ? 0 : l.attemptsOnly ? 1 : 2);

/**
 * The CVE entries of one catalog from a `/api/kev/` page. A page that holds fewer entries than
 * `metadata.count` is truncated and rejected (the catalog would look smaller than it is). Per
 * CVE, a confirmed entry beats a suspected one (and one with success evidence beats one with only
 * attempts), then the earliest `asserted_at` wins.
 */
export function parseCirclKev(doc: unknown, catalog: CirclCatalog): { entries: Map<string, CatalogListing>; newest: string | null } {
  const root = asObject(doc);
  if (!root || !Array.isArray(root.data)) throw new Error('Vulnerability-Lookup KEV: missing "data" array');
  const count = asNumber(asObject(root.metadata)?.count);
  if (count !== null && count > root.data.length) {
    throw new SanityError(`Vulnerability-Lookup KEV: page holds ${root.data.length} of ${count} entries`);
  }
  const entries = new Map<string, CatalogListing>();
  let newest: string | null = null;
  for (const item of root.data) {
    const e = asObject(item);
    if (!e || asString(asObject(e.gcve)?.origin_uuid) !== catalog.origin) continue;
    const id = normalizeCveId(asObject(e.vulnerability)?.vulnId);
    const status = asObject(e.status);
    const reason = asString(status?.status_reason);
    if (!id || status?.exploited !== true || (reason !== 'confirmed' && reason !== 'suspected')) continue;
    const ts = asObject(e.timestamps);
    const added = normalizeYmd(ts?.asserted_at);
    const seen = normalizeYmd(ts?.first_seen_at);
    if (added && (!newest || added > newest)) newest = added;
    const listing: CatalogListing = { catalog: catalog.id, added, status: reason, url: catalog.entryUrl(id), seen };
    if (attemptsOnly(e.evidence)) listing.attemptsOnly = true;
    const prev = entries.get(id);
    const better =
      !prev ||
      rank(listing) > rank(prev) ||
      (rank(listing) === rank(prev) && listing.added !== null && (prev.added === null || listing.added < prev.added));
    if (better) entries.set(id, listing);
  }
  return { entries, newest };
}

async function loadCircl(
  http: HttpClient,
  cfg: typeof CIRCL_KEV | typeof SIBERKAPAN,
  min: number,
  signal?: AbortSignal,
): Promise<SourceResult<Map<string, CatalogListing>>> {
  const catalog: CirclCatalog = { id: cfg.info.id as CatalogId, origin: cfg.origin, entryUrl: cfg.entryUrl };
  const fetched = await http.getSource({
    key: cfg.info.id,
    ext: 'json',
    urls: cfg.urls,
    parse: (body): Parsed<Map<string, CatalogListing>> => {
      const { entries, newest } = parseCirclKev(parseJson(body, cfg.info.name), catalog);
      requireAtLeast(entries.size, min, `${cfg.info.name} CVE entries`);
      return { value: entries, records: entries.size, version: newest };
    },
    minIntervalMs: cfg.minIntervalMs,
    signal,
  });
  return { data: fetched.value, status: statusFromFetch(cfg.info, fetched) };
}

export const loadCirclKev = (http: HttpClient, limits: SanityLimits, signal?: AbortSignal) => loadCircl(http, CIRCL_KEV, limits.circlKevEntries, signal);
export const loadSiberKapan = (http: HttpClient, limits: SanityLimits, signal?: AbortSignal) => loadCircl(http, SIBERKAPAN, limits.siberkapanEntries, signal);

/** Every catalog's listings per CVE, restricted to `ids`, in a fixed catalog order. */
export function mergeCatalogs(ids: ReadonlySet<string>, ...catalogs: (ReadonlyMap<string, CatalogListing> | null)[]): Map<string, CatalogListing[]> {
  const out = new Map<string, CatalogListing[]>();
  for (const catalog of catalogs) {
    if (!catalog) continue;
    for (const [id, listing] of catalog) {
      if (!ids.has(id)) continue;
      const list = out.get(id);
      if (list) list.push(listing);
      else out.set(id, [listing]);
    }
  }
  return out;
}

// ── Exploited listings (the E chips) ───────────────────────────────────────────────────────

/**
 * True when a listing sets the Exploited tier (an E chip, score.ts): every EU KEV listing, and a
 * CIRCL entry that is confirmed with evidence beyond attempts. SiberKapan, CIRCL suspected and
 * CIRCL attempts-only listings are information only and never count. With `asOf` (YYYY-MM-DD, a
 * frozen --now), a listing dated after that day does not exist yet, as in scoring.
 */
export function isExploitedListing(l: CatalogListing, asOf?: string): boolean {
  if (asOf !== undefined && l.added !== null && l.added > asOf) return false;
  return l.catalog === 'eu-kev' || (l.catalog === 'circl-kev' && l.status === 'confirmed' && !l.attemptsOnly);
}

/**
 * The CVE IDs that an exploited listing (isExploitedListing) puts in the data whatever their age,
 * like the CISA KEV catalog's. Null catalogs (unavailable this run) add nothing.
 */
export function exploitedCatalogIds(catalogs: readonly (ReadonlyMap<string, CatalogListing> | null)[], asOf?: string): Set<string> {
  const out = new Set<string>();
  for (const catalog of catalogs) {
    if (!catalog) continue;
    for (const [id, listing] of catalog) if (isExploitedListing(listing, asOf)) out.add(id);
  }
  return out;
}

/** The earliest dated exploited listing among `listings` (none after `asOf`), or null when none is dated. */
export function firstExploitedListing(listings: readonly CatalogListing[] | undefined, asOf?: string): (CatalogListing & { added: string }) | null {
  let first: (CatalogListing & { added: string }) | null = null;
  for (const l of listings ?? []) {
    if (!isExploitedListing(l, asOf) || l.added === null) continue;
    if (!first || l.added < first.added) first = l as CatalogListing & { added: string };
  }
  return first;
}
