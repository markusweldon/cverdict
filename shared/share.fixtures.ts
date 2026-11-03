/** CVE records for the link-preview tests, cut down from real ones in the 2026-11-03 06:50 run. */
import type { CveDetail, KevInfo, Reason } from './contract';

export const GENERATED_AT = '2026-11-03T06:50:18.883Z';
export const ORIGIN = 'https://cverdict-psi.vercel.app';

const r = (id: string, label: string, family: Reason['family'], points: number, polarity: Reason['polarity'] = 'up', at?: string): Reason => ({
  id,
  label,
  polarity,
  family,
  points,
  source: 'computed',
  ...(at ? { at } : {}),
});

const noExploits = (): CveDetail['exploits'] => ({ metasploit: [], nuclei: [], exploitdb: [], poc: { count: 0, vetted: 0, hype: false, top: [] } });

/** A record with every field the contract requires; `over` replaces fields. */
export function detail(over: Partial<CveDetail> = {}): CveDetail {
  return {
    id: 'CVE-2026-109618',
    state: 'PUBLISHED',
    published: '2026-10-22T10:00:00Z',
    reserved: null,
    updated: null,
    cna: 'php',
    title: 'Memory corruption in PHP',
    description: 'A memory corruption bug.',
    cvss: null,
    cwe: [],
    affected: [{ vendor: 'PHP Group', product: 'PHP', purl: null }],
    ssvc: null,
    kev: null,
    epss: null,
    exploits: noExploits(),
    ai_credit: null,
    tags: [],
    batch: null,
    score: { value: 50, tier: 'likely', raw: 50, model: 'v0.1.0' },
    reasons: [],
    unknowns: [],
    timeline: [],
    references: [],
    woke: null,
    ...over,
  };
}

const kev = (due = '2026-10-29', ransomware = 'Unknown'): KevInfo => ({
  date_added: '2026-10-26',
  due_date: due,
  ransomware,
  forensic_triage: true,
  name: 'PHP Memory Corruption Vulnerability',
  required_action: 'Apply mitigations.',
  notes: '',
});
const ssvc = (exploitation: string): CveDetail['ssvc'] => ({ exploitation, automatable: 'no', technical_impact: 'total', version: '2.0.3', timestamp: '2026-10-21T00:00:00.000Z' });
const msf = { name: 'PHP RCE', fullname: 'exploit/multi/http/php_rce', rank: 600, type: 'exploit', url: 'https://github.com/rapid7/metasploit-framework', date: null };
const nuclei = { path: 'http/cves/2026/CVE-2026-109618.yaml', severity: 'critical', url: 'https://github.com/projectdiscovery/nuclei-templates' };
const edb = { id: '52704', verified: true, url: 'https://www.exploit-db.com/exploits/52704', date: '2026-10-22' };

/** CVE-2026-109618 as published: KEV, SSVC active, Nuclei, Exploit-DB, 729 vetted PoC repos. */
export const EXPLOITED_KEV = detail({
  kev: kev(),
  ssvc: ssvc('active'),
  epss: { score: 0.99999, percentile: 0.99998, date: '2026-11-02', model: 'v2026.06.15' },
  exploits: { metasploit: [], nuclei: [nuclei], exploitdb: [edb], poc: { count: 746, vetted: 729, hype: true, top: [] } },
  score: { value: 100, tier: 'exploited', raw: 74, model: 'v0.1.0' },
  reasons: [
    r('kev.listed', 'CISA KEV · added Oct 26 · due Oct 29', 'E', 26, 'up', '2026-10-26'),
    r('ssvc.active', 'CISA SSVC: exploitation active · Oct 21', 'E', 0),
    r('x.nuclei', 'Nuclei template (http · critical): scannable at scale', 'X', 30),
    r('x.exploitdb', 'Exploit-DB 52704 (verified) · Oct 22', 'X', 0),
    r('x.poc', '746 PoC repos (729 vetted) — unverified, may be malware', 'X', 0),
    r('sev.crit_net', 'Critical 9.2 · network (v4.0)', 'SEV', 13),
    r('ssvc.total', 'CISA SSVC: total technical impact', 'SSVC', 8),
    r('ssvc.not_automatable', 'CISA SSVC: not automatable', 'SSVC', -2, 'down'),
    r('prior.product', 'Product in KEV (×3): PHP Group PHP', 'PRIOR', 10),
    r('kev.due', 'KEV due Oct 29 · 5 days ago', 'INFO', 0, 'info'),
  ],
});

export const EXPLOITED_RANSOMWARE = detail({
  id: 'CVE-2013-2551',
  cna: 'mitre',
  affected: [],
  kev: { ...kev('2022-04-18', 'Known'), date_added: '2022-03-28' },
  score: { value: 100, tier: 'exploited', raw: 40, model: 'v0.1.0' },
  reasons: [r('kev.listed', 'CISA KEV · added Mar 28, 2022 · due Apr 18, 2022', 'E', 50), r('kev.ransomware', 'Known ransomware campaign use', 'E', 5)],
});

export const EXPLOITED_SSVC = detail({
  id: 'CVE-2026-110001',
  cna: 'microsoft',
  affected: [{ vendor: 'Microsoft', product: 'Microsoft Exchange Server', purl: null }],
  ssvc: ssvc('active'),
  score: { value: 90, tier: 'exploited', raw: 21, model: 'v0.1.0' },
  reasons: [r('ssvc.active', 'CISA SSVC: exploitation active · Oct 30', 'E', 69)],
});

/** CVE-2026-86471: exploited by the vendor's own word, nothing in KEV. */
export const EXPLOITED_VENDOR = detail({
  id: 'CVE-2026-86471',
  cna: 'apache',
  affected: [{ vendor: 'Apache Software Foundation', product: 'Apache CouchDB', purl: null }],
  score: { value: 100, tier: 'exploited', raw: 32, model: 'v0.1.0' },
  reasons: [r('vendor.itw', 'Vendor: exploited in the wild', 'E', 68)],
});

/** Listed through the CISA-ADP KEV block only (the catalog does not have it yet). */
export const EXPLOITED_ADP_KEV = detail({
  id: 'CVE-2026-110002',
  score: { value: 90, tier: 'exploited', raw: 15, model: 'v0.1.0' },
  reasons: [r('kev.listed', 'CISA KEV · added Nov 2 (per CVE record)', 'E', 75, 'up', '2026-11-02')],
});

export const LIKELY_MSF = detail({
  id: 'CVE-2026-93680',
  cna: 'ibm',
  affected: [{ vendor: 'IBM', product: 'Langflow OSS', purl: null }],
  exploits: { ...noExploits(), metasploit: [msf], poc: { count: 1, vetted: 1, hype: false, top: [] } },
  score: { value: 84, tier: 'likely', raw: 84, model: 'v0.1.0' },
  reasons: [r('x.metasploit', 'Metasploit: exploit/multi/http/langflow_rce (excellent)', 'X', 34), r('x.poc', '1 PoC repo (1 vetted) — unverified, may be malware', 'X', 0), r('sev.crit_net', 'Critical 9.8 · network', 'SEV', 13)],
});

export const LIKELY_NUCLEI = detail({
  id: 'CVE-2026-85714',
  cna: 'GitHub_M',
  affected: [{ vendor: 'Stirling-Tools', product: 'Stirling-PDF', purl: null }],
  exploits: { ...noExploits(), nuclei: [nuclei] },
  score: { value: 58, tier: 'likely', raw: 58, model: 'v0.1.0' },
  reasons: [r('x.nuclei', 'Nuclei template (http · high): scannable at scale', 'X', 30), r('sev.high', 'High 8.8 · network', 'SEV', 1)],
});

export const LIKELY_EDB = detail({
  id: 'CVE-2026-110003',
  cna: 'VulnCheck',
  affected: [{ vendor: 'Acme', product: 'Router', purl: null }],
  exploits: { ...noExploits(), exploitdb: [edb] },
  score: { value: 60, tier: 'likely', raw: 60, model: 'v0.1.0' },
  reasons: [r('x.exploitdb', 'Exploit-DB 52704 (verified) · Oct 22', 'X', 28), r('sev.crit_net', 'Critical 9.8 · network', 'SEV', 13)],
});

export const LIKELY_POC = detail({
  id: 'CVE-2026-102428',
  cna: 'VulDB',
  affected: [{ vendor: 'ordasoft.com', product: 'OrdaSoft Joomla CCK', purl: null }],
  exploits: { ...noExploits(), poc: { count: 2, vetted: 2, hype: false, top: [] } },
  score: { value: 56, tier: 'likely', raw: 56, model: 'v0.1.0' },
  reasons: [r('x.poc', '2 PoC repos (2 vetted) — unverified, may be malware', 'X', 20), r('sev.crit_net', 'Critical 9.3 · network (v4.0)', 'SEV', 13)],
});

export const LIKELY_FUNCTIONAL = detail({
  id: 'CVE-2026-106172',
  cna: 'fortinet',
  affected: [{ vendor: 'Fortinet', product: 'FortiSandbox', purl: null }],
  score: { value: 50, tier: 'likely', raw: 50, model: 'v0.1.0' },
  reasons: [r('vendor.functional', 'Fortinet CVSS vector: functional exploit code exists (E:F)', 'X', 24), r('sev.crit_net', 'Critical 9.6 · network', 'SEV', 13)],
});

export const LIKELY_EPSS = detail({
  id: 'CVE-2025-28137',
  cna: 'mitre',
  affected: [{ vendor: 'n/a', product: 'n/a', purl: null }],
  epss: { score: 0.34113, percentile: 0.97, date: '2026-11-02', model: 'v2026.06.15' },
  exploits: { ...noExploits(), poc: { count: 1, vetted: 1, hype: false, top: [] } },
  score: { value: 69, tier: 'likely', raw: 69, model: 'v0.1.0' },
  reasons: [r('epss.high', 'EPSS 34.1% · 97th pct', 'X', 27), r('x.poc', '1 PoC repo (1 vetted) — unverified, may be malware', 'X', 0), r('sev.crit_net', 'Critical 9.8 · network', 'SEV', 13)],
});

export const LIKELY_SCORE = detail({
  id: 'CVE-2026-83396',
  cna: 'oracle',
  affected: [{ vendor: 'Oracle Corporation', product: 'Oracle Data Integrator', purl: null }],
  score: { value: 50, tier: 'likely', raw: 50, model: 'v0.1.0' },
  reasons: [r('sev.crit_net', 'Critical 9.8 · network', 'SEV', 13), r('prior.product', 'Product in KEV (×2): Oracle Data Integrator', 'PRIOR', 10), r('ssvc.total', 'CISA SSVC: total technical impact', 'SSVC', 8)],
});

export const WATCH = detail({
  id: 'CVE-2026-101416',
  cna: 'oracle',
  affected: [{ vendor: 'Oracle Corporation', product: 'PeopleSoft Enterprise PeopleTools', purl: null }],
  score: { value: 32, tier: 'watch', raw: 32, model: 'v0.1.0' },
  reasons: [r('sev.high', 'High 7.5 · network', 'SEV', 1), r('prior.product', 'Product in KEV (×1): Oracle PeopleSoft', 'PRIOR', 10), r('ssvc.total', 'CISA SSVC: total technical impact', 'SSVC', 8)],
});

export const QUIET_NOTHING = detail({
  id: 'CVE-2026-103061',
  cna: 'Gleam',
  affected: [{ vendor: 'Gleam', product: 'Gleam', purl: null }],
  score: { value: 0, tier: 'quiet', raw: -18, model: 'v0.1.0' },
  reasons: [r('x.none', 'No public exploit after 14 days', 'X', -14, 'down'), r('sev.low', 'Medium 5.3 · network', 'SEV', -13, 'down'), r('prior.none', 'Never in KEV', 'PRIOR', -6, 'down')],
});

/** CVE-2026-89020: Quiet at 24 although a vetted PoC repo counted (+20). It must not read "no evidence". */
export const QUIET_POC = detail({
  id: 'CVE-2026-89020',
  cna: 'VulnCheck',
  affected: [{ vendor: 'MikroTik', product: 'RouterOS', purl: null }],
  ssvc: ssvc('none'),
  epss: { score: 0.00488, percentile: 0.41975, date: '2026-11-02', model: 'v2026.06.15' },
  exploits: { ...noExploits(), poc: { count: 1, vetted: 1, hype: false, top: [] } },
  score: { value: 24, tier: 'quiet', raw: 24, model: 'v0.1.0' },
  reasons: [
    r('x.poc', '1 PoC repo (1 vetted) — unverified, may be malware', 'X', 20, 'up', '2026-10-30T21:26:52.000Z'),
    r('sev.low', 'Medium 5.3 · network (v4.0)', 'SEV', -13, 'down'),
    r('ssvc.not_automatable', 'CISA SSVC: not automatable', 'SSVC', -2, 'down'),
    r('ssvc.partial', 'CISA SSVC: partial technical impact', 'SSVC', -6, 'down'),
    r('prior.product', 'Product in KEV (×5): MikroTik RouterOS', 'PRIOR', 10),
  ],
  woke: { at: '2026-10-30T21:26:52.000Z', signals: [{ kind: 'poc', at: '2026-10-30T21:26:52.000Z', first_seen: false, label: 'first PoC repo on GitHub (unverified)', source: 'poc-github', url: null }] },
});

export const QUIET_CJK = detail({
  id: 'CVE-2026-95597',
  cna: 'Patchstack',
  affected: [{ vendor: 'codemstory', product: '워드프레스 결제 심플페이', purl: null }],
  score: { value: 0, tier: 'quiet', raw: -9, model: 'v0.1.0' },
  reasons: [r('sev.high', 'High 7.1 · network', 'SEV', 1), r('x.none', 'No public exploit after 14 days', 'X', -14, 'down')],
});

/** Upstream text that tries markup, attribute breakout, bidi spoofing, replacement patterns and a flood. */
export const HOSTILE = detail({
  id: 'CVE-2026-99999',
  cna: 'evil<cna>',
  affected: [{ vendor: '"><script>alert(1)</script>‮gnp.exe​ $& $\' $`', product: `${'漏洞 产品 😀 '.repeat(40)}\u0007`, purl: null }],
  epss: { score: Number.NaN, percentile: Number.NaN, date: 'not a date', model: '' },
  kev: { ...kev('2026-02-30'), date_added: 'yesterday' },
  score: { value: 77, tier: 'exploited', raw: 77, model: 'v0.1.0' },
  reasons: [r('kev.listed', 'CISA KEV', 'E', 13), r('prior.product', 'Product in KEV (×2): </title><script>x</script> \u0007bell — dash', 'PRIOR', 10)],
});

/** A minimal shard file around some records. */
export const shardFile = (...items: CveDetail[]) => ({ schema_version: 1, generated_at: GENERATED_AT, items: Object.fromEntries(items.map((d) => [d.id, d])) });
