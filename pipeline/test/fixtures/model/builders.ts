/**
 * Hand-built fixtures for the scoring/emit tests. Independent of ingest: every test states
 * exactly the evidence it cares about on top of a neutral baseline.
 */
import type { Cvss, ExploitEvidence, SourceStatus } from '../../../../shared/contract';
import { buildKevPrior, scoreCve } from '../../../src/score';
import type { Enrichment, IngestResult, KevCatalog, KevRaw, NormalizedCve, PocRepo, ScoredCve } from '../../../src/types';

export const NOW = new Date('2026-10-26T19:30:00Z');
const DAY_MS = 86_400_000;

/** ISO timestamp `days` before NOW. */
export function daysAgo(days: number, now: Date = NOW): string {
  return new Date(now.getTime() - days * DAY_MS).toISOString();
}

/** YYYY-MM-DD `days` before NOW (negative = in the future). */
export function dateAgo(days: number, now: Date = NOW): string {
  return daysAgo(days, now).slice(0, 10);
}

/** CVSS fields for a CVE: `cvss(9.8, 'N')`. */
export function cvss(score: number, av = 'N', version = '3.1', source: Cvss['source'] = 'cna'): Pick<NormalizedCve, 'cvss' | 'cvssMetrics' | 'cnaCvssMissing'> {
  const vector = version === '4.0' ? `CVSS:4.0/AV:${av}/AC:L/AT:N/PR:N/UI:N` : `CVSS:${version}/AV:${av}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`;
  return {
    cvss: { version, score, severity: null, vector, source },
    cvssMetrics: Object.fromEntries(vector.split('/').slice(1).map((kv) => kv.split(':') as [string, string])),
    cnaCvssMissing: source !== 'cna',
  };
}

/**
 * Baseline: 20 days old, CVSS 7.5 network (sev.high +1), no SSVC, vendor "Acme" never in KEV
 * (prior.none −6), no exploit evidence (x.none −14). raw = 15 − 14 + 1 − 6 = −4 → score 0.
 */
export function makeCve(o: Partial<NormalizedCve> = {}): NormalizedCve {
  return {
    id: 'CVE-2026-100001',
    published: daysAgo(20),
    reserved: daysAgo(40),
    updated: daysAgo(19),
    cna: 'acme',
    title: 'Acme Widget SQL injection in login form',
    description: 'A SQL injection vulnerability in the login form of Acme Widget allows remote attackers to read the database.',
    ...cvss(7.5),
    cnaExploitMaturity: [],
    ssvc: null,
    adpKev: null,
    cwe: ['CWE-89'],
    affected: [{ vendor: 'Acme', product: 'Widget', purl: null }],
    tags: [],
    references: ['https://acme.example/advisory/1'],
    aiCredit: null,
    vendorInTheWild: false,
    noiseText: 'acme widget sql injection in login form',
    inWindow: true,
    ...o,
  };
}

export function ssvc(exploitation: string, automatable: string, technical_impact: string, timestamp = daysAgo(19)): NormalizedCve['ssvc'] {
  return { exploitation, automatable, technical_impact, version: '2.0.3', timestamp };
}

export function makeKev(id: string, o: Partial<KevRaw> = {}): KevRaw {
  return {
    cveID: id,
    vendorProject: 'Acme',
    product: 'Widget',
    vulnerabilityName: 'Acme Widget SQL Injection Vulnerability',
    dateAdded: dateAgo(5),
    shortDescription: 'Acme Widget contains a SQL injection vulnerability.',
    requiredAction: 'Apply mitigations per vendor instructions.',
    dueDate: dateAgo(-16),
    knownRansomwareCampaignUse: 'Unknown',
    notes: 'https://acme.example/advisory/1',
    forensicTriage: 'No',
    ...o,
  };
}

export function repo(created: string, stars = 0, fork = false, name = 'poc'): PocRepo {
  return { url: `https://github.com/someone/${name}`, stars, created, fork };
}

export interface EnrichmentSpec {
  kev?: KevRaw[];
  /** id → [epss, percentile] */
  epss?: Record<string, [number, number]>;
  metasploit?: Record<string, ExploitEvidence['metasploit']>;
  nuclei?: Record<string, ExploitEvidence['nuclei']>;
  exploitdb?: Record<string, ExploitEvidence['exploitdb']>;
  poc?: Record<string, PocRepo[]>;
}

export function makeKevCatalog(entries: KevRaw[] = []): KevCatalog {
  return { version: '2026.10.23', dateReleased: '2026-10-23T19:30:18Z', entries: new Map(entries.map((e) => [e.cveID, e])) };
}

export function makeEnrichment(spec: EnrichmentSpec = {}): Enrichment {
  const kev = makeKevCatalog(spec.kev);
  return {
    kev,
    epss: {
      model: 'v2026.06.15',
      scoreDate: dateAgo(0),
      scores: new Map(Object.entries(spec.epss ?? {}).map(([id, [epss, percentile]]) => [id, { epss, percentile }])),
    },
    exploits: {
      metasploit: new Map(Object.entries(spec.metasploit ?? {})),
      nuclei: new Map(Object.entries(spec.nuclei ?? {})),
      exploitdb: new Map(Object.entries(spec.exploitdb ?? {})),
      poc: new Map(Object.entries(spec.poc ?? {})),
    },
    prior: buildKevPrior(kev),
  };
}

export const msf = (fullname: string, rank: number | null = 600, type = 'exploit'): ExploitEvidence['metasploit'][number] => ({
  name: fullname.split('/').pop() ?? fullname,
  fullname,
  rank,
  type,
  url: `https://github.com/rapid7/metasploit-framework/blob/master/modules/${fullname}.rb`,
});

export const nucleiTemplate = (id: string, severity: string | null = 'critical'): ExploitEvidence['nuclei'][number] => ({
  path: `http/cves/2026/${id}.yaml`,
  severity,
  url: `https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/${id}.yaml`,
});

export const edb = (id: string, date: string | null = '2026-10-10', verified = false): ExploitEvidence['exploitdb'][number] => ({
  id,
  verified,
  url: `https://www.exploit-db.com/exploits/${id}`,
  date,
});

/** Score one CVE against a spec (default knob, NOW). */
export function score(cve: NormalizedCve, spec: EnrichmentSpec = {}, knob?: number): ScoredCve {
  return scoreCve(cve, makeEnrichment(spec), { now: NOW, knob });
}

/** Many window CVEs from one CNA on one day, for batch tests. */
export function cohort(n: number, o: Partial<NormalizedCve> & { startId?: number } = {}): NormalizedCve[] {
  const { startId = 200000, ...rest } = o;
  return Array.from({ length: n }, (_, i) =>
    makeCve({
      id: `CVE-2026-${startId + i}`,
      cna: 'microsoft',
      published: '2026-10-13T17:00:00.000Z',
      affected: [{ vendor: 'Microsoft', product: i % 3 === 0 ? 'Windows 11' : i % 3 === 1 ? 'Windows Server 2025' : 'Office', purl: null }],
      ...rest,
    }),
  );
}

/** A complete IngestResult around `cves`, for orchestration and validation tests. */
export function makeIngest(cves: NormalizedCve[], spec: EnrichmentSpec = {}): IngestResult {
  const enr = makeEnrichment(spec);
  const status = (id: SourceStatus['id'], records: number): SourceStatus => ({
    id,
    name: id,
    url: `https://example.test/${id}`,
    ok: true,
    stale: false,
    fetched_at: NOW.toISOString(),
    upstream_version: null,
    records,
    error: null,
    license: 'test',
  });
  return {
    cves,
    history: {
      published: new Map([
        ['2026-09', 14000],
        ['2026-10', cves.length],
      ]),
      reserved: new Map([['2026-10', 20000]]),
      rejected: new Map([['2026-10', 40]]),
      ai: new Map([['2026-10', 3]]),
      totalRecords: 414000,
    },
    rejectedInWindow: 40,
    kev: enr.kev,
    epss: enr.epss,
    exploits: enr.exploits,
    sources: [status('cvelist', 414000), status('kev', enr.kev.entries.size)],
    cvelistCommit: 'e9bdac88b661d98022cbecab20ad4a359f9d6634',
  };
}
