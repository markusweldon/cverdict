/** ProjectDiscovery Nuclei CVE templates (`cves.json`, NDJSON: one template per line). */
import { NUCLEI, type SanityLimits } from '../config';
import type { SourceStatus } from '../../../shared/contract';
import type { ExploitIndex } from '../types';
import type { HttpClient, Parsed } from '../util/http';
import { asObject, asString } from '../util/json';
import { normalizeCveId, sanitizeLine } from '../util/text';
import type { NucleiDatesResult } from './nuclei-history';
import { pushTo, requireAtLeast, statusFromFetch, type SourceResult } from './source';

const TEMPLATE_PATH_RE = /^[\w./-]+\.ya?ml$/;

/** Index templates by `ID`. Lines that are not valid template objects are skipped. */
export function parseNuclei(text: string): { byCve: ExploitIndex['nuclei']; templates: number } {
  const byCve: ExploitIndex['nuclei'] = new Map();
  let templates = 0;
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    let doc: unknown;
    try {
      doc = JSON.parse(line);
    } catch {
      continue;
    }
    const t = asObject(doc);
    const id = normalizeCveId(t?.ID);
    const path = asString(t?.file_path) ?? '';
    if (!t || !id || !TEMPLATE_PATH_RE.test(path) || path.includes('..')) continue;
    templates++;
    const severity = sanitizeLine(asObject(t.Info)?.Severity, 16).toLowerCase() || null;
    const list = byCve.get(id);
    if (list?.some((e) => e.path === path)) continue;
    pushTo(byCve, id, { path, severity, url: `${NUCLEI.blobBase}/${path}` });
  }
  return { byCve, templates };
}

export function parseNucleiBody(body: Buffer, limits: SanityLimits): Parsed<ExploitIndex['nuclei']> {
  const { byCve, templates } = parseNuclei(body.toString('utf8'));
  requireAtLeast(templates, limits.nucleiTemplates, 'Nuclei templates');
  return { value: byCve, records: templates, version: null };
}

export async function loadNuclei(http: HttpClient, limits: SanityLimits, signal?: AbortSignal): Promise<SourceResult<ExploitIndex['nuclei']>> {
  const fetched = await http.getSource({
    key: 'nuclei',
    ext: 'json',
    urls: NUCLEI.urls,
    parse: (body) => parseNucleiBody(body, limits),
    signal,
  });
  return { data: fetched.value, status: statusFromFetch(NUCLEI.info, fetched) };
}

/**
 * The index's status with the template dates folded in (sources/nuclei-history.ts): missing or
 * stale dates leave the templates as they are but mark the source stale, with the reason, and
 * `fetched_at` becomes the time the dates were last current (null without any), so the freshness
 * watchdog's limit on stale sources applies to the dates too.
 */
export function nucleiStatus(index: SourceStatus, dated: NucleiDatesResult): SourceStatus {
  if (!index.ok) return index;
  const status = { ...index, upstream_version: dated.head ?? index.upstream_version };
  if (dated.stale || !dated.dates) {
    const why = `template dates ${dated.dates ? 'from a cached copy' : 'unavailable'}${dated.error ? ` (${dated.error})` : ''}`;
    status.stale = true;
    status.fetched_at = dated.dates && dated.as_of ? [dated.as_of, index.fetched_at].filter((t): t is string => t !== null).sort()[0] : null;
    status.error = status.error ? `${status.error}; ${why}` : why;
  }
  return status;
}
