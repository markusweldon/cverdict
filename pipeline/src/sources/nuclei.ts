/** ProjectDiscovery Nuclei CVE templates (`cves.json`, NDJSON: one template per line). */
import { NUCLEI, type SanityLimits } from '../config';
import type { ExploitIndex } from '../types';
import type { HttpClient, Parsed } from '../util/http';
import { asObject, asString } from '../util/json';
import { normalizeCveId, sanitizeLine } from '../util/text';
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
