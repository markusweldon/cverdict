import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { EPSS, KEV, SANITY, type SanityLimits } from '../../src/config';
import { ingestWith } from '../../src/ingest';
import type { RunContext } from '../../src/types';
import { addDays } from '../../src/util/dates';
import { HttpClient, type FetchLike } from '../../src/util/http';
import { captureLogger, FIXTURES, recordPath, repoWithClone, tempDir, type CapturedLogger } from './helpers';

const NOW = new Date('2026-10-26T19:30:00Z');
const LIMITS: SanityLimits = { ...SANITY, cvelistRecords: 10, kevEntries: 1, epssRows: 1, metasploitModules: 1, nucleiTemplates: 1, exploitdbRows: 1, pocFiles: 1 };

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
  return {
    [KEV.urls[0]]: () => new Response('Forbidden', { status: 403 }),
    [KEV.urls[1]]: () => new Promise<Response>((resolve) => setTimeout(() => resolve(ok(JSON.stringify(kev))()), kevDelayMs)),
    [EPSS.current]: () => new TypeError('fetch failed'),
    [EPSS.daily(ymd(NOW))]: () => new Response('Not Found', { status: 404 }),
    [EPSS.daily(ymd(addDays(NOW, -1)))]: ok(fixtureFile('epss-sample.csv.gz')),
    'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json': ok(JSON.stringify(msf)),
    'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json': ok(fixtureFile('nuclei-sample.json')),
    'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv': ok(edb),
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
    const { ctx, http } = setup();
    const result = await ingestWith(ctx, { cvelistDir: cvelist.clone, pocDir: poc.clone }, { http, limits: LIMITS });

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
    expect([...result.exploits.exploitdb.keys()]).toEqual(['CVE-2026-100878']);
    expect(result.exploits.poc).toEqual(
      new Map([
        ['CVE-2026-110447', [{ url: 'https://github.com/real/poc', stars: 4, created: '2026-10-15T10:00:00.000Z', fork: false, pushed: null }]],
        ['CVE-2026-94216', [{ url: 'https://github.com/other/poc', stars: 1, created: '2026-10-15T10:00:00.000Z', fork: false, pushed: null }]],
      ]),
    );

    const status = Object.fromEntries(result.sources.map((s) => [s.id, s]));
    expect(result.sources.map((s) => s.id)).toEqual(['cvelist', 'cisa-adp', 'kev', 'epss', 'metasploit', 'nuclei', 'exploitdb', 'poc-github']);
    expect(result.sources.every((s) => s.ok && !s.stale && s.license.length > 0 && s.error === null)).toBe(true);
    expect(status.cvelist).toMatchObject({ records: 18, upstream_version: cvelist.commit });
    expect(status['cisa-adp'].records).toBe(13);
    expect(status.kev).toMatchObject({ url: KEV.urls[1], records: 6, upstream_version: '2026.10.23' });
    expect(status.epss).toMatchObject({ url: EPSS.daily('2026-10-25'), records: 8, upstream_version: 'v2026.06.15 2026-10-26' });
    expect(status['poc-github']).toMatchObject({ records: 2, upstream_version: poc.commit });
    expect(status.cvelist.fetched_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('finds catalog-only KEV records even when the catalog arrives after the pass', async () => {
    const cvelist = cvelistRepo();
    const fast = setup();
    const slow = setup({ routes: upstream(500) });
    const deps = (s: typeof fast) => ({ http: s.http, limits: LIMITS });
    const a = await ingestWith(fast.ctx, { cvelistDir: cvelist.clone }, deps(fast));
    const b = await ingestWith(slow.ctx, { cvelistDir: cvelist.clone }, deps(slow));
    const ids = (r: typeof a) => r.cves.map((c) => `${c.id}:${c.inWindow}`).sort();
    expect(ids(b)).toEqual(ids(a));
    expect(b.cves.find((c) => c.id === 'CVE-2026-37106')?.inWindow).toBe(false);
    expect(slow.log.lines.some((l) => /\(1 KEV or woke-up records looked up after the pass\)/.test(l))).toBe(true);
    expect(b.history).toEqual(a.history);
  });

  it('runs offline from the cache written by a previous run, marking HTTP sources stale', async () => {
    const cvelist = cvelistRepo();
    const poc = pocRepo();
    const first = setup();
    await ingestWith(first.ctx, { cvelistDir: cvelist.clone, pocDir: poc.clone }, { http: first.http, limits: LIMITS });

    const offline = setup({ offline: true, cacheDir: first.ctx.cacheDir });
    const result = await ingestWith(offline.ctx, { cvelistDir: cvelist.clone, pocDir: poc.clone }, { http: offline.http, limits: LIMITS });
    expect(offline.requested).toEqual([]);
    expect(result.cves).toHaveLength(11);
    const http = result.sources.filter((s) => ['kev', 'epss', 'metasploit', 'nuclei', 'exploitdb'].includes(s.id));
    expect(http.every((s) => s.ok && s.stale && s.error === null)).toBe(true);
  });

  it('keeps going when optional sources are down, reporting them as unavailable', async () => {
    const cvelist = cvelistRepo();
    const { ctx, http, log } = setup({ routes: {} });
    const result = await ingestWith(ctx, { cvelistDir: cvelist.clone, pocDir: path.join(tempDir(), 'missing') }, { http, limits: LIMITS });
    const failed = result.sources.filter((s) => !s.ok).map((s) => s.id);
    expect(failed).toEqual(['kev', 'epss', 'metasploit', 'nuclei', 'exploitdb', 'poc-github']);
    // Without the KEV catalog, only the window and CISA-ADP KEV blocks decide what is kept.
    expect(result.cves.some((c) => c.id === 'CVE-2026-37106')).toBe(false);
    expect(result.cves.some((c) => c.id === 'CVE-2026-58644')).toBe(true);
    expect(result.kev.entries.size).toBe(0);
    expect(log.lines.some((l) => l.startsWith('WARN ingest: source kev unavailable'))).toBe(true);
  });

  it('fails when the CVE List cannot be read, or has fewer records than the sanity minimum', async () => {
    const { ctx, http } = setup();
    await expect(ingestWith(ctx, { cvelistDir: tempDir() }, { http, limits: LIMITS })).rejects.toThrow(/git rev-parse/);
    await expect(ingestWith(ctx, { cvelistDir: path.join(tempDir(), 'nope') }, { http, limits: LIMITS })).rejects.toThrow(/is not a directory/);

    const cvelist = cvelistRepo();
    const again = setup();
    await expect(
      ingestWith(again.ctx, { cvelistDir: cvelist.clone }, { http: again.http, limits: { ...LIMITS, cvelistRecords: 1000 } }),
    ).rejects.toThrow(/only 18 CVE records/);
  });
});
