import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { PACKAGE_ECOSYSTEMS } from '../../../shared/contract';
import { CIRCL_KEV, EPSS, EU_KEV, KEV, OSV, SANITY, SIBERKAPAN, type SanityLimits } from '../../src/config';
import { ingestWith } from '../../src/ingest';
import type { RunContext } from '../../src/types';
import { addDays } from '../../src/util/dates';
import { HttpClient, type FetchLike } from '../../src/util/http';
import { buildZip } from '../fixtures/zip';
import { captureLogger, FIXTURES, recordPath, repoWithClone, tempDir, type CapturedLogger } from './helpers';

const NOW = new Date('2026-10-26T19:30:00Z');
const LIMITS: SanityLimits = {
  ...SANITY,
  cvelistRecords: 10,
  kevEntries: 1,
  epssRows: 1,
  metasploitModules: 1,
  nucleiTemplates: 1,
  nucleiDates: 1,
  exploitdbRows: 1,
  pocFiles: 1,
  euKevEntries: 1,
  euvdDumpRows: 1,
  circlKevEntries: 1,
  siberkapanEntries: 1,
  osvRecords: Object.fromEntries(PACKAGE_ECOSYSTEMS.map((e) => [e, 0])) as SanityLimits['osvRecords'],
};

const fixtureFile = (name: string) => readFileSync(path.join(FIXTURES, name));

function published(id: string, datePublished: string, extra: Record<string, unknown> = {}) {
  return JSON.stringify({
    cveMetadata: { cveId: id, state: 'PUBLISHED', assignerShortName: 'example', datePublished, dateReserved: '2026-10-01T00:00:00Z' },
    containers: { cna: { descriptions: [{ lang: 'en', value: `Synthetic ${id}` }], ...extra } },
  });
}

/** A cvelistV5-shaped repo: real fixture records, synthetic edge cases and non-record files. */
function cvelistRepo() {
  const files: Record<string, string | Buffer> = {
    'README.md': '# cvelistV5',
    'cves/delta.json': '{"new":[]}',
    'cves/deltaLog.json': '[]',
    'cves/2026/1xxx/CVE-2026-1000.json': '{broken json',
    'cves/2026/1xxx/CVE-2026-1001.json': '{"dataType":"CVE_RECORD"}',
    [recordPath('CVE-2026-200001')]: published('CVE-2026-200001', '2026-10-26T20:00:00Z'),
    [recordPath('CVE-2026-200002')]: JSON.stringify({
      cveMetadata: { cveId: 'CVE-2026-200002', state: 'REJECTED', dateRejected: '2026-10-20T00:00:00Z', dateUpdated: '2026-10-21T00:00:00Z' },
      containers: { cna: { rejectedReasons: [{ lang: 'en', value: 'Rejected.' }] } },
    }),
  };
  for (const name of readdirSync(path.join(FIXTURES, 'records'))) {
    files[recordPath(name.replace(/\.json$/, ''))] = fixtureFile(path.join('records', name));
  }
  return repoWithClone(files);
}

function pocRepo() {
  const repo = (user: string, fork: boolean, stars: number) => ({
    html_url: `https://github.com/${user}/poc`,
    stargazers_count: stars,
    created_at: '2026-10-15T10:00:00Z',
    fork,
  });
  return repoWithClone({
    'README.md': 'PoC-in-GitHub',
    '2026/CVE-2026-110447.json': JSON.stringify([repo('real', false, 4), repo('forker', true, 50)]),
    '2026/CVE-2026-94216.json': JSON.stringify([repo('other', false, 1)]),
  });
}

/** A nuclei-templates-shaped repo with one CVE template (and a helper file that is not one). */
function nucleiRepo() {
  return repoWithClone({ 'http/cves/2026/CVE-2026-0257.yaml': 'id: CVE-2026-0257', 'helpers/payloads/CVE-2026-1.txt': 'x' });
}

type Route = () => Response | Error | Promise<Response>;

function upstream(kevDelayMs = 0): Record<string, Route> {
  const kev = JSON.parse(fixtureFile('kev-sample.json').toString());
  kev.vulnerabilities.push({ ...kev.vulnerabilities[1], cveID: 'CVE-2026-37106', dateAdded: '2026-07-20', dueDate: '2026-08-10' });
  const msf = { ...JSON.parse(fixtureFile('msf-sample.json').toString()), 'exploit_linux/http/collabora_rce': {
    name: 'Collabora CODE RCE', fullname: 'exploit/linux/http/collabora_rce', rank: 600, type: 'exploit',
    references: ['CVE-2026-110447'], path: '/modules/exploits/linux/http/collabora_rce.rb',
  } };
  const edb = `${fixtureFile('exploitdb-sample.csv').toString()}99999,exploits/php/webapps/99999.py,"StarTraining 3.8.1 - IDOR",2026-10-01,x,webapps,java,,2026-10-02,2026-10-02,0,CVE-2026-100878,\n`;
  const ymd = (d: Date) => d.toISOString().slice(0, 10);
  const ok = (body: string | Buffer) => () => new Response(typeof body === 'string' ? body : new Uint8Array(body), { status: 200 });
  // One OSV dump for every ecosystem; only npm keeps its record (the package is in npm).
  const osvZip = buildZip([
    { name: 'GHSA-aaaa-bbbb-cccc.json', data: JSON.stringify({ id: 'GHSA-aaaa-bbbb-cccc', modified: '2026-10-20T00:00:00Z', aliases: ['CVE-2026-110447'], affected: [{ package: { ecosystem: 'npm', name: 'collabora-client' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }) },
    { name: 'MAL-2026-1.json', data: '{}' },
  ]);
  const osv = Object.fromEntries(PACKAGE_ECOSYSTEMS.map((eco) => [`${OSV.base}/${encodeURIComponent(eco)}/all.zip`, ok(osvZip)]));
  return {
    ...osv,
    [KEV.urls[0]]: () => new Response('Forbidden', { status: 403 }),
    [KEV.urls[1]]: () => new Promise<Response>((resolve) => setTimeout(() => resolve(ok(JSON.stringify(kev))()), kevDelayMs)),
    [EPSS.current]: () => new TypeError('fetch failed'),
    [EPSS.daily(ymd(NOW))]: () => new Response('Not Found', { status: 404 }),
    [EPSS.daily(ymd(addDays(NOW, -1)))]: ok(fixtureFile('epss-sample.csv.gz')),
    'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json': ok(JSON.stringify(msf)),
    'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json': ok(fixtureFile('nuclei-sample.json')),
    'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv': ok(edb),
    [EU_KEV.urls[0]]: ok(fixtureFile('euvd-kev-sample.json')),
    [CIRCL_KEV.urls[0]]: ok(fixtureFile('circl-kev-sample.json')),
    [SIBERKAPAN.urls[0]]: ok(fixtureFile('siberkapan-sample.json')),
  };
}

function setup(opts: { offline?: boolean; cacheDir?: string; routes?: Record<string, Route> } = {}) {
  const log: CapturedLogger = captureLogger();
  const routes = opts.routes ?? upstream();
  const requested: string[] = [];
  const fetch: FetchLike = async (url) => {
    requested.push(url);
    const result = (await routes[url]?.()) ?? new TypeError('fetch failed');
    if (result instanceof Error) throw result;
    return result;
  };
  const cacheDir = opts.cacheDir ?? tempDir();
  const ctx: RunContext = { now: NOW, windowDays: 30, windowStart: addDays(NOW, -30), cacheDir, offline: opts.offline ?? false, log };
  const http = new HttpClient({ cacheDir, offline: ctx.offline, log, fetch, sleep: async () => {} });
  return { ctx, http, log, requested };
}

describe('ingestWith (end to end on tiny repositories)', () => {
  it('streams the CVE List, keeps window ∪ KEV records, builds history and restricted enrichment', async () => {
    const cvelist = cvelistRepo();
    const poc = pocRepo();
    const nuclei = nucleiRepo();
    const { ctx, http } = setup();
    const result = await ingestWith(ctx, { cvelistDir: cvelist.clone, pocDir: poc.clone, nucleiDir: nuclei.clone }, { http, limits: LIMITS });

    const kept = new Map(result.cves.map((c) => [c.id, c]));
    const inWindow = result.cves.filter((c) => c.inWindow).map((c) => c.id).sort();
    expect(inWindow).toEqual(['CVE-2026-100878', 'CVE-2026-103664', 'CVE-2026-108706', 'CVE-2026-109733', 'CVE-2026-110447', 'CVE-2026-94220']);
    // Outside the window but KEV-listed (via the CISA-ADP KEV block, or via the catalog only), or
    // woke up: CVE-2026-94216 got its first vetted PoC repo 11 days ago.
    expect(result.cves.filter((c) => !c.inWindow).map((c) => c.id).sort()).toEqual(['CVE-2026-0257', 'CVE-2026-37106', 'CVE-2026-48172', 'CVE-2026-58644', 'CVE-2026-94216']);
    expect(result.wake.signals.get('CVE-2026-94216')).toEqual([
      { kind: 'poc', at: '2026-10-15T10:00:00.000Z', first_seen: false, label: 'first PoC repo on GitHub (unverified)', source: 'poc-github', url: 'https://github.com/nomi-sec/PoC-in-GitHub/blob/master/2026/CVE-2026-94216.json' },
    ]);
    // No previous state: Metasploit and Nuclei start a baseline, nothing counts as new.
    expect(result.wake.tracking).toEqual({ metasploit: NOW.toISOString(), nuclei: NOW.toISOString(), epss: null });
    expect(result.wake.state.metasploit?.known).toContain('CVE-2026-110447');
    // There is no EPSS file from 30 days earlier in this fixture: the jump check is skipped, not "no jumps".
    expect(result.wake.skipped.map((s) => s.kind)).toEqual(['epss']);
    // Published after --now, not KEV: dropped. Before the window, not KEV: dropped.
    expect(kept.has('CVE-2026-200001')).toBe(false);
    expect(kept.has('CVE-2026-100174')).toBe(false);

    expect(result.history.totalRecords).toBe(18);
    expect(result.history.published.get('2026-10')).toBe(5); // the record published after --now is not counted
    expect(result.history.published.get('2026-09')).toBe(3);
    expect(result.history.published.get('2016-10')).toBe(1);
    expect(result.history.reserved.get('2026-10')).toBe(4);
    expect(result.history.rejected.get('2026-08')).toBe(1);
    expect(result.history.rejected.get('2019-02')).toBe(1);
    expect(result.history.rejected.get('2026-10')).toBe(1);
    expect(result.history.ai.get('2026-10')).toBe(3);
    expect(result.rejectedInWindow).toBe(1);

    expect(result.cvelistCommit).toBe(cvelist.commit);
    expect(result.kev.version).toBe('2026.10.23');
    expect(result.kev.entries.size).toBe(6);
    expect(result.epss.model).toBe('v2026.06.15');
    expect([...result.epss.scores.keys()].sort()).toEqual(['CVE-2026-0257', 'CVE-2026-100878', 'CVE-2026-109733', 'CVE-2026-110447', 'CVE-2026-58644', 'CVE-2026-94216']);
    expect([...result.exploits.metasploit.keys()]).toEqual(['CVE-2026-110447']);
    expect([...result.exploits.nuclei.keys()]).toEqual(['CVE-2026-0257']);
    expect([...(result.exploits.nucleiAdded ?? [])]).toEqual([['CVE-2026-0257', { at: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/), commit: nuclei.commit }]]);
    expect(result.backtest).toBeUndefined();
    expect([...result.exploits.exploitdb.keys()]).toEqual(['CVE-2026-100878']);
    expect(result.exploits.poc).toEqual(
      new Map([
        ['CVE-2026-110447', [{ url: 'https://github.com/real/poc', stars: 4, created: '2026-10-15T10:00:00.000Z', fork: false, pushed: null }]],
        ['CVE-2026-94216', [{ url: 'https://github.com/other/poc', stars: 1, created: '2026-10-15T10:00:00.000Z', fork: false, pushed: null }]],
      ]),
    );

    const status = Object.fromEntries(result.sources.map((s) => [s.id, s]));
    expect(result.sources.map((s) => s.id)).toEqual(['cvelist', 'cisa-adp', 'kev', 'epss', 'metasploit', 'nuclei', 'exploitdb', 'eu-kev', 'circl-kev', 'siberkapan', 'poc-github', 'osv']);
    expect(result.sources.every((s) => s.ok && !s.stale && s.license.length > 0 && s.error === null)).toBe(true);
    expect(status.cvelist).toMatchObject({ records: 18, upstream_version: cvelist.commit });
    expect(status['cisa-adp'].records).toBe(13);
    expect(status.kev).toMatchObject({ url: KEV.urls[1], records: 6, upstream_version: '2026.10.23' });
    expect(status.epss).toMatchObject({ url: EPSS.daily('2026-10-25'), records: 8, upstream_version: 'v2026.06.15 2026-10-26' });
    expect(status['poc-github']).toMatchObject({ records: 2, upstream_version: poc.commit });
    expect(status.nuclei).toMatchObject({ upstream_version: nuclei.commit, stale: false });
    expect(status.cvelist.fetched_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(status.osv).toMatchObject({ records: 1, upstream_version: '2026-10-20T00:00:00Z' });
    expect(status['eu-kev']).toMatchObject({ url: EU_KEV.urls[0], records: 3, upstream_version: '2026-10-24' });
    expect(status['circl-kev']).toMatchObject({ records: 2, upstream_version: '2026-10-25', license: 'CC0-1.0 (CIRCL, via Vulnerability-Lookup)' });
    expect(status.siberkapan).toMatchObject({ records: 1, upstream_version: null });
    // Restricted to ingested records; EU KEV dates checked against CISA KEV (110447: before the CISA
    // day, so dated; 0257: the CISA day, so undated and not before it; 100878: EU only).
    expect(Object.fromEntries(result.exploits.catalogs ?? [])).toEqual({
      'CVE-2026-110447': [
        { catalog: 'eu-kev', added: '2026-10-20', status: 'confirmed', url: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-61001' },
        { catalog: 'siberkapan', added: null, status: 'confirmed', url: 'https://vulnerability.circl.lu/vuln/cve-2026-110447', seen: '2026-10-05', attemptsOnly: true },
      ],
      'CVE-2026-0257': [{ catalog: 'eu-kev', added: null, notBefore: '2026-05-29', status: 'confirmed', url: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-0801' }],
      'CVE-2026-100878': [{ catalog: 'eu-kev', added: '2026-10-24', status: 'confirmed', url: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-58113' }],
      'CVE-2026-109733': [{ catalog: 'circl-kev', added: '2026-10-25', status: 'confirmed', url: 'https://vulnerability.circl.lu/vuln/cve-2026-109733', seen: '2026-10-20' }],
      'CVE-2026-94220': [{ catalog: 'circl-kev', added: '2026-10-22', status: 'suspected', url: 'https://vulnerability.circl.lu/vuln/cve-2026-94220', seen: null }],
    });
    expect(result.osv.mirror.ecosystems.npm?.records).toEqual([['GHSA-aaaa-bbbb-cccc', '2026-10-20T00:00:00Z', ['CVE-2026-110447'], [['collabora-client', [['>=0', '<2.0.0']]]]]]);
    expect(PACKAGE_ECOSYSTEMS.map((e) => result.osv.statuses[e].advisories)).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
  });

  it('finds catalog-only KEV records even when the catalog arrives after the pass', async () => {
    const cvelist = cvelistRepo();
    const fast = setup();
    const slow = setup({ routes: upstream(500) });
    const deps = (s: typeof fast) => ({ http: s.http, limits: LIMITS });
    // A missing PoC directory: without one, ingest would clone PoC-in-GitHub over the network.
    const noPoc = path.join(tempDir(), 'missing');
    const nucleiDir = nucleiRepo().clone;
    const a = await ingestWith(fast.ctx, { cvelistDir: cvelist.clone, pocDir: noPoc, nucleiDir }, deps(fast));
    const b = await ingestWith(slow.ctx, { cvelistDir: cvelist.clone, pocDir: noPoc, nucleiDir }, deps(slow));
    const ids = (r: typeof a) => r.cves.map((c) => `${c.id}:${c.inWindow}`).sort();
    expect(ids(b)).toEqual(ids(a));
    expect(b.cves.find((c) => c.id === 'CVE-2026-37106')?.inWindow).toBe(false);
    expect(slow.log.lines.some((l) => /\(1 KEV or woke-up records looked up after the pass\)/.test(l))).toBe(true);
    expect(b.history).toEqual(a.history);
  });

  it('keeps old CVEs that only EU KEV or CIRCL list as exploited, never for SiberKapan, suspected or attempts-only listings', async () => {
    const routes = upstream();
    const eu = JSON.parse(fixtureFile('euvd-kev-sample.json').toString());
    // EU KEV only, listed in the wake period: CVE-2015-1000000 (published 2016).
    eu.push({ ...eu[2], cveId: 'CVE-2015-1000000', euvdId: 'EUVD-2016-0001', sources: ['eukev_kev'], dateAdded: '2026-10-10' });
    const circl = JSON.parse(fixtureFile('circl-kev-sample.json').toString());
    const entry = (vulnId: string, reason: string, asserted: string, evidence: unknown[]) => ({
      ...circl.data[0],
      uuid: `u-${vulnId}-${reason}`,
      vulnerability: { vulnId, altId: [] },
      status: { exploited: true, status_reason: reason },
      timestamps: { asserted_at: asserted, first_seen_at: null },
      evidence,
    });
    circl.data.push(
      // Confirmed with evidence of success, listed months ago: kept, no wake signal.
      entry('CVE-2026-45776', 'confirmed', '2026-03-01T00:00:00Z', [{ signal: 'successful_exploitation' }]),
      // Confirmed but only attempts, or only suspected: information only, not kept.
      entry('CVE-2026-100174', 'confirmed', '2026-10-20T00:00:00Z', [{ signal: 'in_the_wild_attempts' }]),
      entry('CVE-2026-100174', 'suspected', '2026-10-21T00:00:00Z', []),
    );
    circl.metadata.count = circl.data.length;
    const siber = JSON.parse(fixtureFile('siberkapan-sample.json').toString());
    // SiberKapan is information only: its listing keeps nothing.
    siber.data.push({ ...siber.data[0], uuid: 'u-siber', vulnerability: { vulnId: 'CVE-2026-100174', altId: [] } });
    siber.metadata.count = siber.data.length;
    const ok = (body: unknown) => () => new Response(JSON.stringify(body), { status: 200 });
    routes[EU_KEV.urls[0]] = ok(eu);
    routes[CIRCL_KEV.urls[0]] = ok(circl);
    routes[SIBERKAPAN.urls[0]] = ok(siber);
    const { ctx, http } = setup({ routes });
    const result = await ingestWith(ctx, { cvelistDir: cvelistRepo().clone, pocDir: path.join(tempDir(), 'missing'), nucleiDir: nucleiRepo().clone }, { http, limits: LIMITS });

    const outside = result.cves.filter((c) => !c.inWindow).map((c) => c.id).sort();
    expect(outside).toEqual(['CVE-2015-1000000', 'CVE-2026-0257', 'CVE-2026-37106', 'CVE-2026-45776', 'CVE-2026-48172', 'CVE-2026-58644']);
    expect(result.cves.some((c) => c.id === 'CVE-2026-100174')).toBe(false);
    // Neither is in CISA KEV: there is no due date to show.
    expect(result.kev.entries.has('CVE-2015-1000000')).toBe(false);
    expect(result.kev.entries.has('CVE-2026-45776')).toBe(false);
    expect(result.exploits.catalogs?.get('CVE-2015-1000000')).toEqual([
      { catalog: 'eu-kev', added: '2026-10-10', status: 'confirmed', url: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2016-0001' },
    ]);
    // A dated listing in the period is a wake signal; the March CIRCL listing is not.
    expect(result.wake.signals.get('CVE-2015-1000000')).toEqual([
      { kind: 'catalog', at: '2026-10-10', first_seen: false, label: 'listed in ENISA EU KEV', source: 'eu-kev', url: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2016-0001' },
    ]);
    expect(result.wake.signals.has('CVE-2026-45776')).toBe(false);
    expect(result.wake.signals.has('CVE-2026-100174')).toBe(false);
  });

  it('runs offline from the cache written by a previous run, marking HTTP sources stale', async () => {
    const cvelist = cvelistRepo();
    const poc = pocRepo();
    const nuclei = nucleiRepo();
    const first = setup();
    await ingestWith(first.ctx, { cvelistDir: cvelist.clone, pocDir: poc.clone, nucleiDir: nuclei.clone }, { http: first.http, limits: LIMITS });

    const offline = setup({ offline: true, cacheDir: first.ctx.cacheDir });
    const result = await ingestWith(offline.ctx, { cvelistDir: cvelist.clone, pocDir: poc.clone }, { http: offline.http, limits: LIMITS });
    expect(offline.requested).toEqual([]);
    expect(result.cves).toHaveLength(11);
    const http = result.sources.filter((s) => ['kev', 'epss', 'metasploit', 'exploitdb', 'eu-kev', 'circl-kev', 'siberkapan'].includes(s.id));
    expect(http).toHaveLength(7);
    expect(result.exploits.catalogs?.size).toBe(5);
    expect(http.every((s) => s.ok && s.stale && s.error === null)).toBe(true);
    // The first run read its templates clone with --nuclei-dir, which never saves the dates: offline
    // and without a clone there are none, so the templates count without dates and the source says so.
    expect(result.sources.find((s) => s.id === 'nuclei')).toMatchObject({ ok: true, stale: true, fetched_at: null, upstream_version: null, error: 'template dates unavailable (no cached template dates)' });
    expect(result.exploits.nucleiAdded?.size ?? 0).toBe(0);
    expect([...result.exploits.nuclei.keys()]).toEqual(['CVE-2026-0257']);
    void nuclei;
  });

  it('keeps going when optional sources are down, reporting them as unavailable', async () => {
    const cvelist = cvelistRepo();
    const { ctx, http, log } = setup({ routes: {} });
    const result = await ingestWith(ctx, { cvelistDir: cvelist.clone, pocDir: path.join(tempDir(), 'missing'), nucleiDir: path.join(tempDir(), 'missing') }, { http, limits: LIMITS });
    const failed = result.sources.filter((s) => !s.ok).map((s) => s.id);
    expect(failed).toEqual(['kev', 'epss', 'metasploit', 'nuclei', 'exploitdb', 'eu-kev', 'circl-kev', 'siberkapan', 'poc-github', 'osv']);
    expect(result.exploits.catalogs?.size).toBe(0);
    // Without the KEV catalog, only the window and CISA-ADP KEV blocks decide what is kept.
    expect(result.cves.some((c) => c.id === 'CVE-2026-37106')).toBe(false);
    expect(result.cves.some((c) => c.id === 'CVE-2026-58644')).toBe(true);
    expect(result.kev.entries.size).toBe(0);
    expect(log.lines.some((l) => l.startsWith('WARN ingest: source kev unavailable'))).toBe(true);
  });

  it('fails when the CVE List cannot be read, or has fewer records than the sanity minimum', async () => {
    const { ctx, http } = setup();
    // A missing PoC directory: without one, ingest would clone PoC-in-GitHub over the network.
    const pocDir = path.join(tempDir(), 'missing');
    const nucleiDir = pocDir;
    await expect(ingestWith(ctx, { cvelistDir: tempDir(), pocDir, nucleiDir }, { http, limits: LIMITS })).rejects.toThrow(/git rev-parse/);
    await expect(ingestWith(ctx, { cvelistDir: path.join(tempDir(), 'nope'), pocDir, nucleiDir }, { http, limits: LIMITS })).rejects.toThrow(/is not a directory/);

    const cvelist = cvelistRepo();
    const again = setup();
    await expect(
      ingestWith(again.ctx, { cvelistDir: cvelist.clone, pocDir, nucleiDir }, { http: again.http, limits: { ...LIMITS, cvelistRecords: 1000 } }),
    ).rejects.toThrow(/only 18 CVE records/);
  });
});
