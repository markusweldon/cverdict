/** Metasploit Framework module metadata (`db/modules_metadata_base.json`), indexed by referenced CVE. */
import type { ExploitEvidence } from '../../../shared/contract';
import { METASPLOIT, type SanityLimits } from '../config';
import type { ExploitIndex, MetasploitData } from '../types';
import { normalizeIso, normalizeYmd } from '../util/dates';
import type { HttpClient, Parsed } from '../util/http';
import { asArray, asNumber, asObject, asString, parseJson } from '../util/json';
import { normalizeCveId, sanitizeLine } from '../util/text';
import { pushTo, requireAtLeast, statusFromFetch, type SourceResult } from './source';

type Module = ExploitEvidence['metasploit'][number];

const MODULE_PATH_RE = /^\/modules\/[\w./+-]+$/;

/** Exploit modules first, then by rank (600 = excellent … 0 = manual), then name. */
function compareModules(a: Module, b: Module): number {
  return Number(b.type === 'exploit') - Number(a.type === 'exploit') || (b.rank ?? -1) - (a.rank ?? -1) || a.fullname.localeCompare(b.fullname);
}

/** Index modules by the CVE IDs in their `references` (entries like "CVE-2024-1234"). */
export function parseMetasploit(doc: unknown): MetasploitData & { modules: number; newest: string | null } {
  const root = asObject(doc);
  if (!root) throw new Error('Metasploit: expected an object of modules');
  const byCve: ExploitIndex['metasploit'] = new Map();
  const firstModified = new Map<string, string>();
  let modules = 0;
  let newest: string | null = null;
  for (const value of Object.values(root)) {
    const m = asObject(value);
    const fullname = sanitizeLine(m?.fullname, 300);
    if (!m || !fullname) continue;
    modules++;
    const modTime = normalizeIso(m.mod_time);
    if (modTime && (!newest || modTime > newest)) newest = modTime;
    const ids = new Set(asArray(m.references).map(normalizeCveId).filter((id): id is string => id !== null));
    if (ids.size === 0) continue;
    const path = asString(m.path) ?? '';
    const module: Module = {
      name: sanitizeLine(m.name, 300) || fullname,
      fullname,
      rank: asNumber(m.rank),
      type: sanitizeLine(m.type, 32),
      url: MODULE_PATH_RE.test(path) ? `${METASPLOIT.blobBase}${path}` : `https://www.rapid7.com/db/modules/${encodeURI(fullname)}/`,
      date: normalizeYmd(m.disclosure_date),
    };
    for (const id of ids) {
      pushTo(byCve, id, module);
      const first = firstModified.get(id);
      if (modTime && (!first || modTime < first)) firstModified.set(id, modTime);
    }
  }
  for (const list of byCve.values()) list.sort(compareModules);
  return { byCve, firstModified, modules, newest };
}

export function parseMetasploitBody(body: Buffer, limits: SanityLimits): Parsed<MetasploitData> {
  const { byCve, firstModified, modules, newest } = parseMetasploit(parseJson(body, 'Metasploit'));
  requireAtLeast(modules, limits.metasploitModules, 'Metasploit modules');
  return { value: { byCve, firstModified }, records: modules, version: newest };
}

export async function loadMetasploit(
  http: HttpClient,
  limits: SanityLimits,
  signal?: AbortSignal,
): Promise<SourceResult<MetasploitData>> {
  const fetched = await http.getSource({
    key: 'metasploit',
    ext: 'json',
    urls: METASPLOIT.urls,
    parse: (body) => parseMetasploitBody(body, limits),
    signal,
  });
  return { data: fetched.value, status: statusFromFetch(METASPLOIT.info, fetched) };
}
