/**
 * scripts/fast-check.sh against a local HTTP server and a fake `gh`: the compare logic (hash parity
 * with events.ts idsHash, 304s, changed and unchanged catalogs, outages) and every reason not to
 * dispatch.
 */
import { execFile } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { idsHash } from '../../src/events';

const run = promisify(execFile);
const SCRIPT = new URL('../../../scripts/fast-check.sh', import.meta.url).pathname;
const KEV_IDS = ['CVE-2026-1001', 'CVE-2025-2002', 'CVE-2024-3003'];
const EU_IDS = ['CVE-2026-1001', 'CVE-2026-7777'];
const FETCHED = '2026-11-23T16:47:10.000Z';
const LAST_MODIFIED = 'Mon, 23 Nov 2026 15:00:00 GMT';
/** 2026-11-23 17:05 and 17:20 UTC. */
const AT_05 = Date.parse('2026-11-23T17:05:00Z') / 1000;
const AT_20 = Date.parse('2026-11-23T17:20:00Z') / 1000;
const AT_45 = Date.parse('2026-11-23T17:45:00Z') / 1000;

type Handler = (req: IncomingMessage, res: ServerResponse) => void;
let server: Server;
let base: string;
let routes: Record<string, Handler>;
let hits: string[];
let dir: string;

const kevDoc = (ids: string[]) => ({
  catalogVersion: '2026.11.23',
  vulnerabilities: ids.map((cveID, i) => ({ cveID, dateAdded: `2026-11-${String(10 + i).padStart(2, '0')}`, vendorProject: 'Acme', product: 'Widget' })),
});
const euDoc = (ids: string[]) => [...ids.map((cveId) => ({ cveId, sources: ['eukev_kev'] })), { cveId: 'CVE-2020-0001', sources: ['cisa_kev'] }, { cveId: 'CVE-2020-0002', sources: 'eukev_kev' }];
const send = (body: unknown, headers: Record<string, string> = {}): Handler => (_req, res) => {
  res.writeHead(200, { 'content-type': 'application/json', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
};
/** A KEV host that honours If-Modified-Since against LAST_MODIFIED. */
const kevHost = (doc: unknown): Handler => (req, res) => {
  const ims = req.headers['if-modified-since'];
  if (ims && Date.parse(ims) >= Date.parse(LAST_MODIFIED)) {
    res.writeHead(304);
    return res.end();
  }
  send(doc, { 'last-modified': LAST_MODIFIED })(req, res);
};
const down: Handler = (_req, res) => {
  res.writeHead(503);
  res.end('down');
};
const events = (catalogs: unknown = { kev: { version: '2026.11.23', count: 3, ids_sha256: idsHash(KEV_IDS), fetched_at: FETCHED }, eu_kev: { version: null, count: 2, ids_sha256: idsHash(EU_IDS), fetched_at: FETCHED } }) =>
  send({ schema_version: 1, generated_at: '2026-11-23T16:47:29.170Z', catalogs, items: [] });

beforeAll(async () => {
  server = createServer((req, res) => {
    hits.push(req.url ?? '');
    (routes[req.url ?? ''] ?? down)(req, res);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

beforeEach(() => {
  hits = [];
  dir = mkdtempSync(join(tmpdir(), 'fast-check-'));
  routes = { '/raw/v1/events.json': events(), '/kev': kevHost(kevDoc(KEV_IDS)), '/mirror': kevHost(kevDoc(KEV_IDS)), '/eu': send(euDoc(EU_IDS)) };
  return () => rmSync(dir, { recursive: true, force: true });
});

interface GhRun {
  status: string;
  conclusion: string;
  event: string;
  createdAt: string;
  displayTitle: string;
}

/** Run the script at `now` with a fake gh that lists `runs` and logs dispatches. */
async function check(now: number, runs: GhRun[] = [], extra: Record<string, string> = {}) {
  writeFileSync(join(dir, 'runs.json'), JSON.stringify(runs));
  const gh = join(dir, 'gh');
  writeFileSync(
    gh,
    `#!/usr/bin/env bash\nif [[ $1 == run ]]; then cat "${join(dir, 'runs.json')}"; elif [[ $1 == workflow ]]; then echo "$*" >>"${join(dir, 'dispatch.log')}"; else exit 2; fi\n`,
  );
  chmodSync(gh, 0o755);
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    HOME: dir,
    TMPDIR: dir,
    NO_PROXY: '*',
    RAW_BASE: `${base}/raw`,
    KEV_URLS: `${base}/kev ${base}/mirror`,
    EU_KEV_URL: `${base}/eu`,
    GH: gh,
    NOW: String(now),
    GITHUB_STEP_SUMMARY: join(dir, 'summary.md'),
    ...extra,
  };
  const { stdout } = await run('bash', [SCRIPT], { env, timeout: 20_000 });
  const log = join(dir, 'dispatch.log');
  return { stdout, dispatched: existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n') : [], summary: readFileSync(join(dir, 'summary.md'), 'utf8') };
}

const ago = (now: number, minutes: number) => new Date((now - minutes * 60) * 1000).toISOString().replace('.000Z', 'Z');

describe('scripts/fast-check.sh', () => {
  it('stays quiet when CISA answers 304 and EU KEV lists the same CVEs', async () => {
    const r = await check(AT_05);
    expect(r.dispatched).toEqual([]);
    expect(r.stdout).toContain('CISA KEV: not modified');
    expect(r.stdout).toContain('EU KEV: same 2 CVEs');
    expect(r.summary).toContain('Nothing new upstream.');
  });

  it('hashes ids exactly like the pipeline: order, case, spaces, duplicates and junk do not matter', async () => {
    const messy = { vulnerabilities: [...kevDoc(['cve-2024-3003 ', 'CVE-2026-1001', 'CVE-2025-2002', 'CVE-2026-1001']).vulnerabilities, { cveID: 'not a cve', dateAdded: '2026-11-01' }, { cveID: 'CVE-2026-9999' }, 'x'] };
    routes['/kev'] = send(messy, { 'last-modified': 'Mon, 23 Nov 2026 17:00:00 GMT' });
    routes['/eu'] = send([...euDoc(['cve-2026-7777']), { cveId: 'CVE-2026-1001 ', sources: ['cisa_kev', 'eukev_kev'] }]);
    const r = await check(AT_05);
    expect(r.stdout).toContain('CISA KEV: same 3 CVEs as published.');
    expect(r.stdout).toContain('EU KEV: same 2 CVEs as published.');
    expect(r.dispatched).toEqual([]);
  });

  it('dispatches a refresh when CISA lists a new CVE, and says which are newest', async () => {
    routes['/kev'] = send(kevDoc([...KEV_IDS, 'CVE-2026-4444']), { 'last-modified': 'Mon, 23 Nov 2026 17:01:00 GMT' });
    const r = await check(AT_20);
    expect(r.dispatched).toEqual(['workflow run refresh.yml -f reason=fast-check -f fresh=none']);
    expect(r.summary).toContain('CISA KEV changed: 4 CVEs upstream, 3 published. Newest: CVE-2026-4444 (2026-11-13)');
    // EU KEV is only checked in the first quarter of the hour.
    expect(hits).not.toContain('/eu');
  });

  it('asks for a fresh EU KEV download when ENISA lists a new CVE', async () => {
    routes['/eu'] = send(euDoc([...EU_IDS, 'CVE-2026-8888']));
    const r = await check(AT_05);
    expect(r.dispatched).toEqual(['workflow run refresh.yml -f reason=fast-check -f fresh=eu-kev']);
    // Not again within 20 hours of a fresh EU KEV dispatch.
    const again = await check(AT_05 + 3600, [{ status: 'completed', conclusion: 'success', event: 'workflow_dispatch', createdAt: ago(AT_05 + 3600, 60), displayTitle: 'refresh-data (fast-check, eu-kev)' }]);
    expect(again.dispatched).toEqual(['workflow run refresh.yml -f reason=fast-check -f fresh=eu-kev']);
    expect(again.stdout).toContain('in the last 20 hours; not dispatching');
  });

  it('falls back to the mirror when the primary fails, with the same rule', async () => {
    routes['/kev'] = down;
    routes['/mirror'] = send(kevDoc([...KEV_IDS, 'CVE-2026-5555']));
    const r = await check(AT_20);
    expect(hits).toEqual(['/raw/v1/events.json', '/kev', '/mirror']);
    expect(r.dispatched).toHaveLength(1);
  });

  it('turns network errors into warnings and exits 0 without dispatching', async () => {
    routes['/kev'] = down;
    routes['/mirror'] = down;
    routes['/eu'] = down;
    const r = await check(AT_05);
    expect(r.stdout).toContain('::warning title=Fast check::CISA KEV: no source answered');
    expect(r.stdout).toContain('::warning title=Fast check::EU KEV:');
    expect(r.dispatched).toEqual([]);
    routes['/raw/v1/events.json'] = down;
    const noRaw = await check(AT_05);
    expect(noRaw.stdout).toContain('Could not read the published events.json');
  });

  it('does nothing while a refresh is pending, near the hourly run, or before the snapshot exists', async () => {
    const pending = await check(AT_20, [{ status: 'in_progress', conclusion: '', event: 'schedule', createdAt: ago(AT_20, 3), displayTitle: 'refresh-data (schedule)' }]);
    expect(pending.stdout).toContain('queued or running');
    expect(hits).toEqual([]);
    // No hourly run to go by: the timer's minute 47. At 17:45 it is 2 minutes away.
    const late = await check(AT_45);
    expect(late.stdout).toContain('The next hourly refresh is due in 2 minutes (from minute 47)');
    routes['/raw/v1/events.json'] = send({ schema_version: 1, items: [] });
    const old = await check(AT_20);
    expect(old.stdout).toContain('no catalog snapshot yet');
    const none = await check(AT_20, [], {});
    expect(none.dispatched).toEqual([]);
  });

  it('times the hour from the last hourly run, not from the minute it happens to start at', async () => {
    // The timer ran at 17:30 (late). At 17:45 the next one is 45 minutes away, and EU KEV is due.
    const timer = { status: 'completed', conclusion: 'success', event: 'workflow_dispatch', createdAt: '2026-11-23T17:30:00Z', displayTitle: 'refresh-data (manual, none)' };
    const at45 = await check(AT_45, [timer]);
    expect(at45.stdout).not.toContain('due in');
    expect(hits).toContain('/eu');
    // At 18:22 the next timer run is 8 minutes away.
    const at22 = await check(AT_20 + 3600 + 120, [timer]);
    expect(at22.stdout).toContain('The next hourly refresh is due in 8 minutes (from the last hourly run)');
    // A run of ours does not move the hour; neither does an hourly run older than 2 hours.
    hits = [];
    const ours = { ...timer, createdAt: '2026-11-23T17:00:00Z', displayTitle: 'refresh-data (fast-check, none)' };
    const old = { ...timer, createdAt: '2026-11-23T14:00:00Z' };
    await check(AT_20, [ours, old]);
    expect(hits).not.toContain('/eu');
  });

  it('does not loop on a mirror without Last-Modified once our refresh has seen upstream', async () => {
    routes['/kev'] = down;
    routes['/mirror'] = send(kevDoc([...KEV_IDS, 'CVE-2026-5555']));
    const ours = { status: 'completed', conclusion: 'success', event: 'workflow_dispatch', createdAt: ago(AT_20, 60), displayTitle: 'refresh-data (fast-check, none)' };
    const later = { ...ours, event: 'schedule', createdAt: ago(AT_20, 50), displayTitle: 'refresh-data (schedule)' };
    const r = await check(AT_20, [ours, later]);
    expect(r.dispatched).toEqual([]);
    expect(r.stdout).toContain('sends no Last-Modified');
    // Our dispatch failed, or nothing has run since it: try again (after the 45 minutes).
    const failed = await check(AT_20, [{ ...ours, conclusion: 'failure' }]);
    expect(failed.dispatched).toHaveLength(1);
  });

  it('keeps upstream text on one line, so it cannot start a workflow command', async () => {
    const doc = kevDoc([...KEV_IDS, 'CVE-2026-4444']);
    doc.vulnerabilities.push({ cveID: 'CVE-2026-1\n::error::forged', dateAdded: '2026-11-30', vendorProject: 'x', product: 'y' });
    doc.vulnerabilities.push({ cveID: 'CVE-2026-6666', dateAdded: '2026-11-29\n::stop-commands::z', vendorProject: 'x', product: 'y' });
    routes['/kev'] = send(doc, { 'last-modified': 'Mon, 23 Nov 2026 17:01:00 GMT' });
    const r = await check(AT_20, [], { DRY_RUN: '1' });
    expect(r.stdout).toContain('Newest: CVE-2026-4444 (2026-11-13)');
    expect(r.stdout.split('\n').filter((l) => l.startsWith('::') && !l.startsWith('::warning title=Fast check::'))).toEqual([]);
    expect(r.stdout).not.toContain('forged');
  });

  it('rate-limits its own dispatches to one per 45 minutes', async () => {
    routes['/kev'] = send(kevDoc([...KEV_IDS, 'CVE-2026-4444']));
    const r = await check(AT_20, [{ status: 'completed', conclusion: 'failure', event: 'workflow_dispatch', createdAt: ago(AT_20, 30), displayTitle: 'refresh-data (fast-check, none)' }]);
    expect(r.dispatched).toEqual([]);
    expect(r.stdout).toContain('in the last 45 minutes');
    // A manual run is not ours.
    const manual = await check(AT_20, [{ status: 'completed', conclusion: 'success', event: 'workflow_dispatch', createdAt: ago(AT_20, 400), displayTitle: 'refresh-data (manual, none)' }]);
    expect(manual.dispatched).toHaveLength(1);
  });

  it('does not chase an id difference that a later successful run has already seen', async () => {
    // Upstream changed at 15:00; a refresh started at 16:47 and succeeded, yet the hashes differ.
    routes['/kev'] = send(kevDoc([...KEV_IDS, 'CVE-2026-4444']), { 'last-modified': LAST_MODIFIED });
    const r = await check(AT_20, [{ status: 'completed', conclusion: 'success', event: 'schedule', createdAt: '2026-11-23T16:47:03Z', displayTitle: 'refresh-data (schedule)' }]);
    expect(r.dispatched).toEqual([]);
    expect(r.stdout).toContain('a successful refresh started after this version');
  });

  it('reports without dispatching in a dry run, and skips a catalog the run could not load', async () => {
    routes['/kev'] = send(kevDoc([...KEV_IDS, 'CVE-2026-4444']));
    const dry = await check(AT_20, [], { DRY_RUN: '1' });
    expect(dry.dispatched).toEqual([]);
    expect(dry.stdout).toContain('Dry run: would start refresh.yml');
    routes['/raw/v1/events.json'] = events({ kev: null, eu_kev: null });
    const nulls = await check(AT_05);
    expect(nulls.dispatched).toEqual([]);
    expect(hits.filter((h) => h === '/kev')).toHaveLength(1);
  });
});
