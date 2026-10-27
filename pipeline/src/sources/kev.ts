/** CISA Known Exploited Vulnerabilities catalog (cisa.gov, then the cisagov/kev-data mirror, then cache). */
import { KEV, type SanityLimits } from '../config';
import type { KevCatalog, KevRaw } from '../types';
import { normalizeIso, normalizeYmd } from '../util/dates';
import type { CacheMeta, HttpClient, Parsed } from '../util/http';
import { asArray, asObject, asString, parseJson } from '../util/json';
import { normalizeCveId, sanitizeLine, sanitizeText } from '../util/text';
import { requireAtLeast, SanityError, statusFromFetch, type SourceResult } from './source';

/** Parse a catalog document. Entries without a valid CVE ID or dateAdded are skipped; first entry per ID wins. */
export function parseKevCatalog(doc: unknown): KevCatalog {
  const root = asObject(doc);
  if (!root || !Array.isArray(root.vulnerabilities)) throw new Error('KEV: missing "vulnerabilities" array');
  const entries = new Map<string, KevRaw>();
  for (const item of asArray(root.vulnerabilities)) {
    const v = asObject(item);
    const id = normalizeCveId(v?.cveID);
    const dateAdded = normalizeYmd(v?.dateAdded);
    if (!v || !id || !dateAdded || entries.has(id)) continue;
    const entry: KevRaw = {
      cveID: id,
      vendorProject: sanitizeLine(v.vendorProject, 200),
      product: sanitizeLine(v.product, 200),
      vulnerabilityName: sanitizeLine(v.vulnerabilityName, 300),
      dateAdded,
      shortDescription: sanitizeText(v.shortDescription, 2_000),
      requiredAction: sanitizeText(v.requiredAction, 2_000),
      dueDate: normalizeYmd(v.dueDate) ?? '',
      knownRansomwareCampaignUse: sanitizeLine(v.knownRansomwareCampaignUse, 32),
      notes: sanitizeText(v.notes, 4_000),
    };
    const cwes = asArray(v.cwes)
      .map((c) => sanitizeLine(c, 32))
      .filter(Boolean);
    if (cwes.length > 0) entry.cwes = cwes;
    const forensic = asString(v.forensicTriage);
    if (forensic !== null) entry.forensicTriage = sanitizeLine(forensic, 16);
    entries.set(id, entry);
  }
  return {
    version: sanitizeLine(root.catalogVersion, 64) || null,
    dateReleased: normalizeIso(root.dateReleased),
    entries,
  };
}

/** Parse + sanity: at least `kevEntries` entries and never below `kevMinRatioOfCached` of the cached copy. */
export function parseKevBody(body: Buffer, cached: CacheMeta | null, limits: SanityLimits): Parsed<KevCatalog> {
  const catalog = parseKevCatalog(parseJson(body, 'KEV'));
  const count = catalog.entries.size;
  requireAtLeast(count, limits.kevEntries, 'KEV entries');
  const previous = cached?.records ?? 0;
  if (previous > 0 && count < previous * limits.kevMinRatioOfCached) {
    throw new SanityError(`KEV shrank to ${count} entries from ${previous} cached`);
  }
  return { value: catalog, records: count, version: catalog.version };
}

export async function loadKev(http: HttpClient, limits: SanityLimits, signal?: AbortSignal): Promise<SourceResult<KevCatalog>> {
  const fetched = await http.getSource({
    key: 'kev',
    ext: 'json',
    urls: KEV.urls,
    parse: (body, cached) => parseKevBody(body, cached, limits),
    signal,
  });
  return { data: fetched.value, status: statusFromFetch(KEV.info, fetched) };
}
