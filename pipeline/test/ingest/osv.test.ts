import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { PACKAGE_ECOSYSTEMS } from '../../../shared/contract';
import { OSV, SANITY, type OsvConfig, type SanityLimits } from '../../src/config';
import { compactRecord, isValidLite, loadOsv, mirrorPath, type OsvMirror } from '../../src/sources/osv';
import { HttpClient, type FetchLike } from '../../src/util/http';
import { buildZip, type ZipFile } from '../fixtures/zip';
import { captureLogger, tempDir } from './helpers';

const T0 = Date.parse('2026-11-03T08:00:00Z');
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const LIMITS: SanityLimits = { ...SANITY, osvRecords: Object.fromEntries(PACKAGE_ECOSYSTEMS.map((e) => [e, 1])) as SanityLimits['osvRecords'] };
const url = (eco: string, file: string) => `${OSV.base}/${encodeURIComponent(eco)}/${file}`;

interface RecordSpec {
  cves?: string[];
  name?: string;
  eco?: string;
  events?: Record<string, string>[];
  versions?: string[];
  withdrawn?: string;
  modified?: string;
}
function osvRecord(id: string, spec: RecordSpec = {}) {
  return {
    id,
    modified: spec.modified ?? '2026-11-01T00:00:00Z',
    aliases: spec.cves ?? ['CVE-2026-10001'],
    ...(spec.withdrawn ? { withdrawn: spec.withdrawn } : {}),
    affected: [
      {
        package: { ecosystem: spec.eco ?? 'npm', name: spec.name ?? 'left-pad' },
        ranges: [{ type: 'SEMVER', events: spec.events ?? [{ introduced: '0' }, { fixed: '1.3.1' }] }],
        ...(spec.versions ? { versions: spec.versions } : {}),
      },
    ],
  };
}
const entry = (rec: { id: string }): ZipFile => ({ name: `${rec.id}.json`, data: JSON.stringify(rec) });

type Handler = (headers: Record<string, string>, signal?: AbortSignal) => Response | Promise<Response>;

/** Fetch stub: routes by URL, records every call with its headers. Unknown URLs fail like a dead network. */
function stub(routes: Record<string, Handler>) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const fetch: FetchLike = async (u, init) => {
    const headers = { ...(init.headers as Record<string, string>) };
    calls.push({ url: u, headers });
    const route = routes[u];
    if (!route) throw new TypeError('fetch failed');
    return route(headers, init.signal ?? undefined);
  };
  return { fetch, calls };
}

const ok = (body: Buffer | string, headers: Record<string, string> = {}) => new Response(typeof body === 'string' ? body : new Uint8Array(body), { status: 200, headers });

/** A modified_id.csv route that honours Range (or ignores it). */
function csv(lines: string[], opts: { ignoreRange?: boolean } = {}): Handler {
  const body = Buffer.from(lines.map((l) => `${l}\n`).join(''));
  return (headers) => {
    const m = /^bytes=(\d+)-(\d+)$/.exec(headers.range ?? '');
    if (!m || opts.ignoreRange) return ok(body);
    const start = Number(m[1]);
    const end = Math.min(Number(m[2]), body.length - 1);
    if (start >= body.length) return new Response('', { status: 416 });
    return new Response(new Uint8Array(body.subarray(start, end + 1)), { status: 206, headers: { 'content-range': `bytes ${start}-${end}/${body.length}` } });
  };
}

function setup(opts: { cacheDir?: string; clock?: number; offline?: boolean; osvDir?: string; config?: Partial<OsvConfig>; limits?: SanityLimits; routes: Record<string, Handler> }) {
  const { fetch, calls } = stub(opts.routes);
  const log = captureLogger();
  const cacheDir = opts.cacheDir ?? tempDir('osv-test-');
  const tmpDir = tempDir('osv-tmp-');
  const http = new HttpClient({ cacheDir, offline: opts.offline ?? false, log, fetch, sleep: async () => {}, retryDelaysMs: [] });
  const run = () =>
    loadOsv({ http, cacheDir, offline: opts.offline ?? false, log, limits: opts.limits ?? LIMITS, osvDir: opts.osvDir, clock: () => opts.clock ?? T0, tmpDir, config: opts.config });
  return { run, calls, log, cacheDir, tmpDir };
}

const base = [
  osvRecord('GHSA-aaaa-aaaa-aaaa', { cves: ['CVE-2026-10001'], name: 'left-pad' }),
  osvRecord('GHSA-bbbb-bbbb-bbbb', { cves: ['CVE-2026-10002', 'CVE-2026-10003'], name: 'lodash', events: [{ introduced: '4.0.0' }, { fixed: '4.17.21' }] }),
  osvRecord('GHSA-cccc-cccc-cccc', { cves: ['CVE-2026-10004'], name: 'minimist', modified: '2026-11-02T12:00:00Z' }),
];
const npmZip = (records: object[] = base, extra: ZipFile[] = []) => buildZip([...records.map((r) => entry(r as { id: string })), ...extra]);

/** A first run that leaves a full npm copy in the cache. */
async function seeded(records: object[] = base) {
  const first = setup({ routes: { [url('npm', 'all.zip')]: () => ok(npmZip(records), { etag: '"v1"' }) } });
  const r = await first.run();
  expect(r.data.statuses.npm).toMatchObject({ ok: true, stale: false, advisories: records.length });
  return first.cacheDir;
}

describe('compactRecord', () => {
  it('keeps only this ecosystem, merges split ranges, adds extra versions and marks unreadable ranges', () => {
    const rec = {
      id: 'GHSA-xxxx-yyyy-zzzz',
      modified: '2026-11-01T00:00:00Z',
      aliases: ['CVE-2026-1001', 'CVE-2026-1001', 'not-a-cve', 'CVE-2026-1'],
      affected: [
        { package: { ecosystem: 'npm', name: 'bootstrap' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '3.0.0' }, { fixed: '3.4.1' }] }], versions: ['3.0.0', '2.9.9'] },
        { package: { ecosystem: 'npm', name: 'bootstrap' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.3.1' }] }, { type: 'SEMVER', events: [{ introduced: '3.0.0' }, { fixed: '3.4.1' }] }] },
        { package: { ecosystem: 'Maven', name: 'org.webjars:bootstrap' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }] },
        { package: { ecosystem: 'npm', name: 'git-only' }, ranges: [{ type: 'GIT', repo: 'x', events: [{ introduced: 'abc' }] }] },
        { package: { ecosystem: 'npm', name: 'odd' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { limit: '2.0.0' }, { fixed: 'has space' }] }] },
      ],
    };
    expect(compactRecord(rec, 'npm')).toEqual([
      'GHSA-xxxx-yyyy-zzzz',
      '2026-11-01T00:00:00Z',
      ['CVE-2026-1001'],
      [
        ['bootstrap', [['>=3.0.0', '<3.4.1'], ['>=4.0.0', '<4.3.1']], ['2.9.9']],
        ['git-only', [['?git=unknown']]],
        ['odd', [['>=0', '?limit=2.0.0', '?invalid=']]],
      ],
    ]);
    expect(compactRecord(rec, 'Maven')?.[3]).toEqual([['org.webjars:bootstrap', [['>=0']]]]);
    expect(compactRecord(rec, 'PyPI')).toBeNull();
  });

  it('drops withdrawn records, records without a CVE, malformed IDs and databases without a licence notice', () => {
    const counters = { prefixes: new Map<string, number>(), malformed: 0 };
    expect(compactRecord(osvRecord('GHSA-aaaa-aaaa-aaaa', { withdrawn: '2026-11-01T00:00:00Z' }), 'npm', counters)).toBeNull();
    expect(compactRecord(osvRecord('GHSA-aaaa-aaaa-aaaa', { cves: ['GHSA-other'] }), 'npm', counters)).toBeNull();
    expect(compactRecord(osvRecord('../../etc/passwd'), 'npm', counters)).toBeNull();
    expect(compactRecord(osvRecord('OSV-2020-111'), 'npm', counters)).toBeNull();
    expect(compactRecord(osvRecord('EEF-CVE-2023-1'), 'npm', counters)).toBeNull();
    expect(compactRecord({ ...osvRecord('GHSA-aaaa-aaaa-aaaa'), modified: 'yesterday' }, 'npm', counters)).toBeNull();
    expect(compactRecord(null, 'npm', counters)).toBeNull();
    expect([...counters.prefixes]).toEqual([['OSV', 1], ['EEF', 1]]);
    expect(counters.malformed).toBe(3);
    // A CVE ID as the record's own ID counts.
    expect(compactRecord({ ...osvRecord('PYSEC-2021-1', { eco: 'PyPI' }), aliases: ['CVE-2021-9999'] }, 'PyPI')?.[2]).toEqual(['CVE-2021-9999']);
  });

  it('caps listed versions and treats names like __proto__ as names', () => {
    const versions = Array.from({ length: 1_200 }, (_, i) => `9.${i}.0`);
    const lite = compactRecord(osvRecord('GHSA-aaaa-aaaa-aaaa', { name: '__proto__', events: [{ introduced: '0' }, { fixed: '1.0.0' }], versions }), 'npm')!;
    expect(lite[3][0][0]).toBe('__proto__');
    expect(lite[3][0][1]).toEqual([['>=0', '<1.0.0'], ['?versions=capped']]);
    expect(lite[3][0][2]).toHaveLength(1_000);
    expect(isValidLite(lite)).toBe(true);
  });

  it('isValidLite rejects what compactRecord never writes', () => {
    const good = compactRecord(base[0], 'npm')!;
    expect(isValidLite(good)).toBe(true);
    expect(isValidLite([...good.slice(0, 3), [['left-pad', [['> 1']]]]])).toBe(false);
    expect(isValidLite(['OSV-2020-1', ...good.slice(1)])).toBe(false);
    expect(isValidLite([good[0], good[1], [], good[3]])).toBe(false);
    expect(isValidLite([good[0], good[1], good[2], [['x\u0000', [['>=0']]]]])).toBe(false);
    expect(isValidLite({})).toBe(false);
  });
});

describe('loadOsv: full sync', () => {
  it('reads all.zip, skips MAL- entries and unknown prefixes, writes the mirror, and deletes the download', async () => {
    const zip = npmZip(base, [
      { name: 'MAL-2026-1.json', data: '{not even json' },
      entry(osvRecord('OSV-2020-111', { cves: ['CVE-2020-1'] })),
      entry(osvRecord('GHSA-dddd-dddd-dddd', { eco: 'PyPI', name: 'x' })),
    ]);
    const t = setup({ routes: { [url('npm', 'all.zip')]: () => ok(zip, { etag: '"v1"' }) } });
    const { data, status } = await t.run();
    expect(data.statuses.npm).toEqual({ ok: true, stale: false, fetched_at: new Date(T0).toISOString(), modified: '2026-11-02T12:00:00Z', advisories: 3, error: null });
    expect(data.mirror.ecosystems.npm?.records.map((r) => r[0])).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb', 'GHSA-cccc-cccc-cccc']);
    expect(data.mirror.ecosystems.npm?.zip_etag).toBe('"v1"');
    expect(t.log.lines.some((l) => l.includes('skipped 1 records with the prefix OSV'))).toBe(true);
    // The other seven ecosystems had no route and no copy.
    expect(status).toMatchObject({ id: 'osv', ok: true, stale: true, records: 3 });
    expect(status.error).toContain('PyPI: fetch failed');
    expect(readdirSync(t.tmpDir)).toEqual([]);
    const mirror = JSON.parse(gunzipSync(readFileSync(mirrorPath(t.cacheDir))).toString()) as OsvMirror;
    expect(Object.keys(mirror.ecosystems)).toEqual(['npm']);
  });

  it('leaves an ecosystem without a copy ok: false, and the source down when none has one', async () => {
    const { data, status } = await setup({ routes: {} }).run();
    expect(PACKAGE_ECOSYSTEMS.every((e) => !data.statuses[e].ok)).toBe(true);
    expect(status).toMatchObject({ ok: false, stale: true, records: 0, fetched_at: null });
  });

  it('keeps the records on a 304 and resets the full sync time', async () => {
    const cacheDir = await seeded();
    const later = T0 + 8 * DAY;
    const t = setup({ cacheDir, clock: later, routes: { [url('npm', 'all.zip')]: () => new Response(null, { status: 304 }) } });
    const { data } = await t.run();
    expect(t.calls.find((c) => c.url === url('npm', 'all.zip'))?.headers['if-none-match']).toBe('"v1"');
    expect(data.statuses.npm).toMatchObject({ ok: true, stale: false, advisories: 3 });
    expect(data.mirror.ecosystems.npm?.full_sync_at).toBe(new Date(later).toISOString());
  });

  it('falls back to the cached copy when all.zip is over its byte cap, or redirected off the bucket', async () => {
    const cacheDir = await seeded();
    const later = T0 + 8 * DAY;
    const big = setup({ cacheDir, clock: later, config: { limits: { ...OSV.limits, zipBytes: 100 } }, routes: { [url('npm', 'all.zip')]: () => ok(npmZip()) } });
    const r1 = await big.run();
    expect(r1.data.statuses.npm).toMatchObject({ ok: true, stale: true, advisories: 3 });
    expect(r1.data.statuses.npm.error).toContain('larger than');

    const moved = setup({
      cacheDir,
      clock: later,
      routes: { [url('npm', 'all.zip')]: () => Object.defineProperty(ok(npmZip()), 'url', { value: 'https://evil.example/all.zip' }) },
    });
    const r2 = await moved.run();
    expect(r2.data.statuses.npm).toMatchObject({ ok: true, stale: true });
    expect(r2.data.statuses.npm.error).toBe('redirected to evil.example, which is not allowed');
  });

  it('rejects a dump below its floor or far below the cached copy', async () => {
    const cacheDir = await seeded();
    const later = T0 + 8 * DAY;
    const shrunk = setup({ cacheDir, clock: later, routes: { [url('npm', 'all.zip')]: () => ok(npmZip(base.slice(0, 1))) } });
    const r = await shrunk.run();
    expect(r.data.statuses.npm).toMatchObject({ ok: true, stale: true, advisories: 3 });
    expect(r.data.statuses.npm.error).toContain('fewer than 90% of the cached 3');

    const floor = setup({ limits: { ...LIMITS, osvRecords: { ...LIMITS.osvRecords, npm: 10 } }, routes: { [url('npm', 'all.zip')]: () => ok(npmZip()) } });
    expect((await floor.run()).data.statuses.npm).toMatchObject({ ok: false, error: 'only 3 usable records (expected at least 10)' });
  });

  it('reads local dumps with --osv-dir, and uses the mirror only when offline', async () => {
    const dir = tempDir('osv-dir-');
    writeFileSync(path.join(dir, 'npm.zip'), npmZip());
    const local = setup({ osvDir: dir, routes: {} });
    const r = await local.run();
    expect(local.calls).toEqual([]);
    expect(r.data.statuses.npm).toMatchObject({ ok: true, stale: false, advisories: 3 });
    expect(r.data.statuses.PyPI).toMatchObject({ ok: false });

    const offline = setup({ cacheDir: local.cacheDir, offline: true, routes: {} });
    const o = await offline.run();
    expect(offline.calls).toEqual([]);
    expect(o.data.statuses.npm).toMatchObject({ ok: true, stale: true, advisories: 3, error: null });
    expect(o.data.statuses.Go).toMatchObject({ ok: false, error: 'offline; no cached copy' });
  });

  it('validates the mirror again when it is read back from the cache', async () => {
    const cacheDir = await seeded();
    const file = mirrorPath(cacheDir);
    const mirror = JSON.parse(gunzipSync(readFileSync(file)).toString()) as OsvMirror;
    mirror.ecosystems.npm!.records.push(['GHSA-zzzz-zzzz-zzzz', '2026-11-01T00:00:00Z', ['CVE-2026-1'], [['x', [['>= 1.0 && rm -rf']]]]] as never);
    (mirror.ecosystems as Record<string, unknown>)['constructor'] = { records: [] };
    writeFileSync(file, gzipSync(JSON.stringify(mirror)));
    const t = setup({ cacheDir, offline: true, routes: {} });
    const { data } = await t.run();
    expect(data.statuses.npm.advisories).toBe(3);
    expect(t.log.lines.some((l) => l.includes('dropped 1 invalid records'))).toBe(true);

    writeFileSync(file, 'not gzip');
    const broken = setup({ cacheDir, offline: true, routes: {} });
    expect((await broken.run()).data.statuses.npm.ok).toBe(false);
  });
});

describe('loadOsv: incremental sync', () => {
  const at = (h: number) => new Date(Date.parse('2026-11-02T12:00:00Z') + h * HOUR).toISOString().replace('.000Z', 'Z');

  it('reads the CSV head down to the cursor minus the overlap, fetches changed records and skips MAL- IDs', async () => {
    const cacheDir = await seeded();
    const changed = osvRecord('GHSA-bbbb-bbbb-bbbb', { cves: ['CVE-2026-10002'], name: 'lodash', events: [{ introduced: '4.0.0' }, { fixed: '4.17.22' }], modified: at(3) });
    const added = osvRecord('GHSA-eeee-eeee-eeee', { cves: ['CVE-2026-10009'], name: 'express', modified: at(2) });
    const t = setup({
      cacheDir,
      clock: T0 + HOUR,
      routes: {
        [url('npm', 'modified_id.csv')]: csv([`${at(4)},MAL-2026-9`, `${at(3)},GHSA-bbbb-bbbb-bbbb`, `${at(2)},GHSA-eeee-eeee-eeee`, `${at(-1)},GHSA-ffff-ffff-ffff`, `${at(-3)},GHSA-gggg-gggg-gggg`]),
        [url('npm', 'GHSA-bbbb-bbbb-bbbb.json')]: () => ok(JSON.stringify(changed)),
        [url('npm', 'GHSA-eeee-eeee-eeee.json')]: () => ok(JSON.stringify(added)),
        [url('npm', 'GHSA-ffff-ffff-ffff.json')]: () => new Response('gone', { status: 404 }),
      },
    });
    const { data } = await t.run();
    const fetched = t.calls.map((c) => c.url.slice(OSV.base.length));
    // at(-1) is inside the 2-hour overlap, at(-3) is not; MAL- is never fetched.
    expect(fetched.filter((u) => u.startsWith('/npm/')).sort()).toEqual(['/npm/GHSA-bbbb-bbbb-bbbb.json', '/npm/GHSA-eeee-eeee-eeee.json', '/npm/GHSA-ffff-ffff-ffff.json', '/npm/modified_id.csv']);
    expect(t.calls.find((c) => c.url.endsWith('/npm/modified_id.csv'))?.headers.range).toBe('bytes=0-16383');
    const npm = data.mirror.ecosystems.npm!;
    expect(npm.records.map((r) => r[0])).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb', 'GHSA-cccc-cccc-cccc', 'GHSA-eeee-eeee-eeee']);
    expect(npm.records[1][3][0][1]).toEqual([['>=4.0.0', '<4.17.22']]);
    expect(npm.cursor).toBe(at(4));
    expect(data.statuses.npm).toMatchObject({ ok: true, stale: false, advisories: 4, modified: at(4) });
  });

  it('extends the range request until the cursor, and reads a server that ignores Range up to the cap', async () => {
    const cacheDir = await seeded();
    const lines = [...Array.from({ length: 40 }, (_, i) => `${at(5)},MAL-2026-${1000 + i}`), `${at(4)},GHSA-aaaa-aaaa-aaaa`, `${at(-5)},GHSA-old0-old0-old0`];
    const rec = { [url('npm', 'GHSA-aaaa-aaaa-aaaa.json')]: () => ok(JSON.stringify(osvRecord('GHSA-aaaa-aaaa-aaaa', { name: 'left-pad-2', modified: at(4) }))) };
    const ranged = setup({ cacheDir, clock: T0 + HOUR, config: { csvHeadBytes: 256 }, routes: { [url('npm', 'modified_id.csv')]: csv(lines), ...rec } });
    const r1 = await ranged.run();
    const ranges = ranged.calls.filter((c) => c.url.endsWith('modified_id.csv')).map((c) => c.headers.range);
    expect(ranges.length).toBeGreaterThan(1);
    expect(ranges[1]).toMatch(/^bytes=\d+-\d+$/);
    expect(r1.data.mirror.ecosystems.npm?.records[0][3][0][0]).toBe('left-pad-2');

    // Server ignores Range and sends 2 KB; the cap is 1.5 KB: cut off, parsed up to the cap.
    const padded = [`${at(4)},GHSA-aaaa-aaaa-aaaa`, `${at(-5)},GHSA-old0-old0-old0`, ...Array.from({ length: 60 }, () => `${at(-6)},GHSA-pad0-pad0-pad0`)];
    const whole = setup({ cacheDir, clock: T0 + HOUR, config: { csvMaxBytes: 1536 }, routes: { [url('npm', 'modified_id.csv')]: csv(padded, { ignoreRange: true }), ...rec } });
    const r2 = await whole.run();
    expect(Buffer.byteLength(padded.join('\n'))).toBeGreaterThan(1536);
    expect(r2.data.statuses.npm).toMatchObject({ ok: true, stale: false });
    expect(whole.calls.filter((c) => c.url.endsWith('.json')).map((c) => c.url)).toEqual([url('npm', 'GHSA-aaaa-aaaa-aaaa.json')]);
  });

  it('asks for a full sync when the CSV has an unreadable time or too many changes', async () => {
    for (const [lines, config] of [
      [[`yesterday,GHSA-aaaa-aaaa-aaaa`], {}],
      [[`${at(4)},GHSA-aaaa-aaaa-aaaa`, `${at(3)},GHSA-bbbb-bbbb-bbbb`, `${at(2)},GHSA-cccc-cccc-cccc`], { maxChangedIds: 2 }],
    ] as const) {
      const cacheDir = await seeded();
      const t = setup({ cacheDir, clock: T0 + HOUR, config, routes: { [url('npm', 'modified_id.csv')]: csv([...lines]), [url('npm', 'all.zip')]: () => ok(npmZip(), { etag: '"v2"' }) } });
      const { data } = await t.run();
      expect(t.calls.some((c) => c.url === url('npm', 'all.zip'))).toBe(true);
      expect(t.calls.filter((c) => c.url.endsWith('.json'))).toEqual([]);
      expect(data.mirror.ecosystems.npm?.zip_etag).toBe('"v2"');
    }
  });

  it('never fetches an ID that fails the pattern or has no licence notice, and drops a record that answers with another ID', async () => {
    const cacheDir = await seeded();
    const t = setup({
      cacheDir,
      clock: T0 + HOUR,
      routes: {
        [url('npm', 'modified_id.csv')]: csv([`${at(4)},../../../evil`, `${at(4)},GHSA-x/y`, `${at(4)},OSV-2026-1`, `${at(3)},GHSA-bbbb-bbbb-bbbb`]),
        [url('npm', 'GHSA-bbbb-bbbb-bbbb.json')]: () => ok(JSON.stringify(osvRecord('GHSA-aaaa-aaaa-aaaa', { name: 'hijack' }))),
      },
    });
    const { data } = await t.run();
    expect(t.calls.map((c) => c.url).filter((u) => /evil|x%2Fy|x\/y|OSV-2026/.test(u))).toEqual([]);
    const npm = data.mirror.ecosystems.npm!;
    expect(npm.records.map((r) => [r[0], r[3][0][0]])).toEqual([['GHSA-aaaa-aaaa-aaaa', 'left-pad'], ['GHSA-bbbb-bbbb-bbbb', 'lodash'], ['GHSA-cccc-cccc-cccc', 'minimist']]);
    expect(t.log.lines.some((l) => l.includes('GHSA-bbbb-bbbb-bbbb.json holds the record GHSA-aaaa-aaaa-aaaa; dropped'))).toBe(true);
  });

  it('removes withdrawn records', async () => {
    const cacheDir = await seeded();
    const t = setup({
      cacheDir,
      clock: T0 + HOUR,
      routes: {
        [url('npm', 'modified_id.csv')]: csv([`${at(3)},GHSA-cccc-cccc-cccc`]),
        [url('npm', 'GHSA-cccc-cccc-cccc.json')]: () => ok(JSON.stringify(osvRecord('GHSA-cccc-cccc-cccc', { withdrawn: at(3), modified: at(3) }))),
      },
    });
    expect((await t.run()).data.mirror.ecosystems.npm?.records.map((r) => r[0])).toEqual(['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb']);
  });

  it('removes nothing and marks the ecosystem stale when too many records answer 404', async () => {
    const cacheDir = await seeded();
    const ids = ['GHSA-aaaa-aaaa-aaaa', 'GHSA-bbbb-bbbb-bbbb', 'GHSA-cccc-cccc-cccc'];
    const routes: Record<string, Handler> = { [url('npm', 'modified_id.csv')]: csv(ids.map((id) => `${at(3)},${id}`)) };
    for (const id of ids) routes[url('npm', `${id}.json`)] = () => new Response('', { status: 404 });
    const t = setup({ cacheDir, clock: T0 + HOUR, config: { max404: 3 }, routes });
    const { data, status } = await t.run();
    expect(data.statuses.npm).toMatchObject({ ok: true, stale: true, advisories: 3 });
    expect(data.statuses.npm.error).toContain('3 changed records answered 404');
    expect(status.error).toContain('npm: 3 changed records answered 404');
  });

  it('keeps a stale copy when the network is down, and applies nothing when one record fails', async () => {
    const cacheDir = await seeded();
    const down = setup({ cacheDir, clock: T0 + HOUR, routes: {} });
    const r = await down.run();
    expect(r.data.statuses.npm).toMatchObject({ ok: true, stale: true, advisories: 3, fetched_at: new Date(T0).toISOString() });
    expect(r.status).toMatchObject({ ok: true, stale: true, fetched_at: new Date(T0).toISOString() });

    const partial = setup({
      cacheDir,
      clock: T0 + HOUR,
      routes: {
        [url('npm', 'modified_id.csv')]: csv([`${at(3)},GHSA-cccc-cccc-cccc`, `${at(3)},GHSA-eeee-eeee-eeee`]),
        [url('npm', 'GHSA-cccc-cccc-cccc.json')]: () => ok(JSON.stringify(osvRecord('GHSA-cccc-cccc-cccc', { withdrawn: at(3) }))),
        [url('npm', 'GHSA-eeee-eeee-eeee.json')]: () => new Response('busy', { status: 503 }),
      },
    });
    const p = await partial.run();
    expect(p.data.statuses.npm).toMatchObject({ ok: true, stale: true, advisories: 3, error: expect.stringContaining('HTTP 503') });
    expect(p.data.mirror.ecosystems.npm?.cursor).toBe('2026-11-02T12:00:00Z');
  });

  it('reads the full dump again once the copy is 7 days old', async () => {
    const cacheDir = await seeded();
    const t = setup({ cacheDir, clock: T0 + 7 * DAY, routes: { [url('npm', 'all.zip')]: () => ok(npmZip()) } });
    await t.run();
    expect(t.calls.filter((c) => c.url.startsWith(`${OSV.base}/npm/`)).map((c) => c.url)).toEqual([url('npm', 'all.zip')]);
  });
});

describe('the OSV step budget', () => {
  it('stops waiting at the budget and keeps every cached copy', async () => {
    const cacheDir = await seeded();
    mkdirSync(path.dirname(mirrorPath(cacheDir)), { recursive: true });
    // Like fetch: never answers, but gives up when the request is aborted.
    const never: Handler = (_h, signal) => new Promise<Response>((_, reject) => signal?.addEventListener('abort', () => reject(signal.reason)));
    const t = setup({ cacheDir, clock: T0 + HOUR, config: { budgetMs: 50 }, routes: { [url('npm', 'modified_id.csv')]: never } });
    const { data } = await t.run();
    expect(data.statuses.npm).toMatchObject({ ok: true, stale: true, advisories: 3 });
    expect(data.statuses.npm.error).toBe('the OSV step ran out of time (0.05 s)');
  });
});
