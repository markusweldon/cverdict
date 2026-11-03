import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SCHEMA_VERSION, rowsFromTable, type CveShard, type Meta, type PackagesFile, type ReceiptsFile, type RowTable, type WokeFile, type WokeItem } from '../../../shared/contract';
import { BUDGETS } from '../../src/config';
import { shardOf } from '../../../shared/shard';
import { buildOutput } from '../../src/emit/build';
import { PATHS, SHARD_NAMES, writeFiles } from '../../src/emit/json';
import { formatSizeTable, validateOutput } from '../../src/validate';
import { emptyOsvData, type OsvCopy, type OsvData, type OsvLite } from '../../src/sources/osv';
import type { Logger } from '../../src/types';
import { detectWakes } from '../../src/woke';
import { NOW, cohort, daysAgo, makeCve, makeIngest, makeKev, makeKevCatalog, msf, repo } from '../fixtures/model/builders';

const cves = [
  ...cohort(55),
  makeCve({ id: 'CVE-2026-100001', title: '<script>alert(1)</script>', published: '2026-10-25T08:00:00.000Z' }),
  makeCve({ id: 'CVE-2021-44228', published: '2021-12-10T00:00:00.000Z', inWindow: false, affected: [{ vendor: 'Apache', product: 'Log4j2', purl: null }] }),
];
const spec = {
  kev: [makeKev('CVE-2026-100001'), makeKev('CVE-2021-44228', { vendorProject: 'Apache', product: 'Log4j2', dateAdded: '2021-12-10', dueDate: '2021-12-24' })],
  metasploit: { 'CVE-2026-200003': [msf('exploit/windows/http/x')] },
  epss: { 'CVE-2026-200004': [0.2, 0.99] as [number, number] },
};
const OLD = 'CVE-2019-0001';
cves.push(makeCve({ id: OLD, published: '2019-05-01T00:00:00.000Z', inWindow: false }));
const pocs = { [OLD]: [repo(daysAgo(8))] };
const wake = detectWakes({
  now: NOW,
  kev: makeKevCatalog(spec.kev),
  exploitdb: { byCve: new Map(), firstAdded: new Map(), added: new Map() },
  metasploit: new Map(Object.entries(spec.metasploit)),
  nuclei: new Map(),
  poc: new Map(Object.entries(pocs)),
  epss: null,
  epssPast: null,
  epssPastError: null,
  previous: null,
  previousAt: null,
});
// OSV mirror: Log4Shell (KEV, not in the window), a window CVE in npm and PyPI, and an untracked CVE.
const copy = (records: OsvLite[]): OsvCopy => ({ full_sync_at: NOW.toISOString(), zip_etag: null, cursor: NOW.toISOString(), fetched_at: NOW.toISOString(), records });
const osv: OsvData = emptyOsvData('no copy');
osv.mirror.ecosystems = {
  Maven: copy([['GHSA-jfh8-c2jp-5v3q', '2026-10-01T00:00:00Z', ['CVE-2021-44228'], [['org.apache.logging.log4j:log4j-core', [['>=2.13.0', '<2.15.0'], ['>=2.0-beta9', '<2.3.1']]]]]]),
  npm: copy([
    ['GHSA-aaaa-bbbb-cccc', '2026-10-25T00:00:00Z', ['CVE-2026-100001', 'CVE-2099-0001'], [['left-pad', [['>=0', '<1.3.1']], ['0.0.0-x']]]],
    ['GHSA-zzzz-zzzz-zzzz', '2026-10-25T00:00:00Z', ['CVE-2015-9999'], [['untracked', [['>=0', '<1.0.0']]]]],
  ]),
  PyPI: copy([['PYSEC-2026-1', '2026-10-25T00:00:00Z', ['CVE-2026-100001'], [['Django_Foo', [['>=1.0', '<2.0']]]]]]),
};
for (const eco of ['Maven', 'npm', 'PyPI'] as const) {
  osv.statuses[eco] = { ok: true, stale: false, fetched_at: NOW.toISOString(), modified: NOW.toISOString(), advisories: osv.mirror.ecosystems[eco]!.records.length, error: null };
}
const built = buildOutput({ ingest: makeIngest(cves, { ...spec, poc: pocs, wake, osv }), now: NOW, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://example.test' });

let dir: string;
beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'validate-'));
  await writeFiles(dir, built.files);
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const read = <T>(p: string): T => JSON.parse(readFileSync(join(dir, p), 'utf8')) as T;
const write = (p: string, v: unknown) => writeFileSync(join(dir, p), typeof v === 'string' ? v : JSON.stringify(v));
const firstIndexId = () => rowsFromTable(read<RowTable>(PATHS.index))[0].id;

describe('validateOutput', () => {
  it('accepts a freshly built tree and logs a size table', () => {
    const lines: string[] = [];
    const log: Logger = { info: (m) => lines.push(m), warn: (m) => lines.push(`WARN ${m}`), error: (m) => lines.push(`ERROR ${m}`) };
    const result = validateOutput(dir, log);
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.ok).toBe(true);
    // 11 JSON files (incl. woke.json, receipts.json, state.json, packages.json), the shards, 4 feeds.
    expect(result.files).toBe(11 + SHARD_NAMES.length + 4);
    expect(lines[0]).toMatch(/^file\s+bytes\s+gzip\s+budget\s+status$/);
    expect(lines.some((l) => l.startsWith('v1/index.json'))).toBe(true);
    expect(lines.some((l) => l.startsWith('v1/cve/*.json (256'))).toBe(true);
  });

  it('the built tree is internally consistent', () => {
    const meta = read<Meta>(PATHS.meta);
    expect(meta.counts.window_published).toBe(56);
    expect(meta.counts.batches_window).toBe(1);
    expect(meta.counts.kev_total).toBe(2);
    expect(Object.keys(meta.definitions).sort()).toEqual(Object.keys(meta.counts).sort());
    // KEV CVEs outside the window get a detail shard but no index row
    const log4j = read<CveShard>(PATHS.shard(shardOf('CVE-2021-44228')));
    expect(log4j.items['CVE-2021-44228'].score.tier).toBe('exploited');
    expect(rowsFromTable(read<RowTable>(PATHS.index)).some((r) => r.id === 'CVE-2021-44228')).toBe(false);
  });

  it('catches a missing shard', () => {
    const shard = PATHS.shard(shardOf(firstIndexId()));
    unlinkSync(join(dir, shard));
    const result = validateOutput(dir);
    expect(result.ok).toBe(false);
    expect(result.errors).toContain(`missing ${shard}`);
    expect(result.errors.some((e) => /index rows have no detail shard entry/.test(e))).toBe(true);
  });

  it('catches a row whose detail is missing from its shard', () => {
    const id = firstIndexId();
    const path = PATHS.shard(shardOf(id));
    const shard = read<CveShard>(path);
    delete shard.items[id];
    write(path, shard);
    // That CVE is also named in packages.json, whose row now has no detail either.
    expect(validateOutput(dir).errors).toEqual([`1 index rows have no detail shard entry (first: ${id})`, `${PATHS.packages}: 1 cves rows have no detail shard entry (first: ${id})`]);
  });

  it('catches a detail stored in the wrong shard', () => {
    const id = firstIndexId();
    const right = shardOf(id);
    const wrong = SHARD_NAMES.find((s) => s !== right)!;
    const a = read<CveShard>(PATHS.shard(right));
    const b = read<CveShard>(PATHS.shard(wrong));
    b.items[id] = a.items[id];
    delete a.items[id];
    write(PATHS.shard(right), a);
    write(PATHS.shard(wrong), b);
    expect(validateOutput(dir).errors).toEqual(expect.arrayContaining([`${id} is stored in shard ${wrong}, expected ${right}`]));
  });

  it('catches invalid JSON and a wrong schema_version', () => {
    write(PATHS.batches, '{"schema_version":');
    write(PATHS.changes, { schema_version: SCHEMA_VERSION + 1, generated_at: NOW.toISOString(), items: [] });
    const { errors } = validateOutput(dir);
    expect(errors.some((e) => e.startsWith(`${PATHS.batches}: invalid JSON`))).toBe(true);
    expect(errors).toContain(`${PATHS.changes}: schema_version is ${SCHEMA_VERSION + 1}, expected ${SCHEMA_VERSION}`);
  });

  it('catches meta counts that disagree with the index', () => {
    const meta = read<Meta>(PATHS.meta);
    meta.counts.window_published += 1;
    meta.counts.window_by_tier.quiet += 1;
    write(PATHS.meta, meta);
    const { errors } = validateOutput(dir);
    expect(errors).toContain('meta.counts.window_published is 57, index has 56 rows');
    expect(errors.some((e) => e.startsWith('meta.counts.window_by_tier.quiet'))).toBe(true);
  });

  it('catches signal rows that are not in the index', () => {
    const signal = read<RowTable>(PATHS.signal);
    const extra = [...signal.rows[0]];
    extra[0] = 'CVE-2026-999999';
    signal.rows.push(extra);
    write(PATHS.signal, signal);
    const { errors } = validateOutput(dir);
    expect(errors).toContain('1 signal rows are not in the index (first: CVE-2026-999999)');
  });

  it('warns over budget and fails beyond 150%', () => {
    const stats = read<Record<string, unknown>>(PATHS.stats);
    write(PATHS.stats, { ...stats, pad: randomBytes(90 * 1024).toString('base64') });
    let result = validateOutput(dir);
    expect(result.ok).toBe(true);
    expect(result.warnings.some((w) => w.startsWith(`${PATHS.stats}:`) && w.includes('over its'))).toBe(true);

    write(PATHS.stats, { ...stats, pad: randomBytes(130 * 1024).toString('base64') });
    result = validateOutput(dir);
    expect(result.ok).toBe(false);
    expect(result.errors.some((e) => e.startsWith(`${PATHS.stats}:`) && e.includes('exceeds'))).toBe(true);
    expect(formatSizeTable(result.sizes)).toMatch(/v1\/stats\.json.*fail/);
  });

  it('checks feed framing', () => {
    write(PATHS.kevDueIcs, 'BEGIN:VCALENDAR\nEND:VCALENDAR\n');
    write(PATHS.signalFeed, '<html></html>');
    const { errors } = validateOutput(dir);
    expect(errors).toContain(`${PATHS.kevDueIcs}: not an iCalendar object`);
    expect(errors).toContain(`${PATHS.kevDueIcs}: bare LF line ending`);
    expect(errors).toContain(`${PATHS.signalFeed}: not an Atom document`);
  });

  it('checks woke.json against the index, the shards and its counts', () => {
    const woke = read<WokeFile>(PATHS.woke);
    expect(woke.items.map((i) => i.id)).toEqual([OLD]);
    expect(read<CveShard>(PATHS.shard(shardOf(OLD))).items[OLD].woke?.signals[0].kind).toBe('poc');
    const inWindow = rowsFromTable(read<RowTable>(PATHS.index))[0];
    const fake: WokeItem = { ...woke.items[0], id: inWindow.id, row: inWindow };
    write(PATHS.woke, { ...woke, items: [...woke.items, fake], counts: { ...woke.counts, poc: 5 } });
    const { errors } = validateOutput(dir);
    expect(errors).toContain(`${PATHS.woke}: 1 bad items (first: ${inWindow.id} was published in the window)`);
    expect(errors).toContain(`${PATHS.woke}: counts.poc is 5, items imply 2`);
  });

  it('requires woke.json, state.json and the woke feed, and budgets them', () => {
    unlinkSync(join(dir, PATHS.state));
    write(PATHS.woke, { ...read<WokeFile>(PATHS.woke), pad: randomBytes(100 * 1024).toString('base64') });
    const { errors } = validateOutput(dir);
    expect(errors).toContain(`missing ${PATHS.state}`);
    expect(errors.some((e) => e.startsWith(`${PATHS.woke}:`) && e.includes('exceeds'))).toBe(true);
  });

  it('requires receipts.json, budgets it, and checks that its figures match its lists', () => {
    expect(BUDGETS.gzipBytes[PATHS.receipts]).toBeGreaterThan(0);
    const r = read<ReceiptsFile>(PATHS.receipts);
    write(PATHS.receipts, { ...r, forward: { ...r.forward, eligible: 3, methods: r.forward.methods.map((m) => ({ ...m, before: 2 })) } });
    const { errors } = validateOutput(dir);
    expect(errors.some((e) => e.includes('forward counts do not match'))).toBe(true);
    expect(errors.some((e) => e.includes('forward.methods.cverdict does not add up'))).toBe(true);
    write(PATHS.receipts, { ...r, backtest: { hindsight: false } });
    expect(validateOutput(dir).errors.some((e) => e.includes('not marked as hindsight'))).toBe(true);
    unlinkSync(join(dir, PATHS.receipts));
    expect(validateOutput(dir).errors).toContain(`missing ${PATHS.receipts}`);
  });

  it('budgets every fixed output path', () => {
    const fixed: string[] = Object.values(PATHS).filter((p) => typeof p === 'string');
    const budgets: Readonly<Record<string, number>> = BUDGETS.gzipBytes;
    expect(fixed.filter((p) => !(budgets[p] > 0))).toEqual([]);
  });

  it('enforces the file count limit', () => {
    for (let i = 0; i < 40; i++) write(`v1/extra-${i}.txt`, 'x');
    expect(validateOutput(dir).errors).toContain(`${271 + 40} files emitted; the limit is 300`);
  });

  it('builds packages.json from the OSV mirror with the index rows of the CVEs it names', () => {
    const p = read<PackagesFile>(PATHS.packages);
    expect(rowsFromTable(p.cves).map((r) => r.id)).toEqual(['CVE-2021-44228', 'CVE-2026-100001']);
    expect(Object.keys(p.packages)).toEqual(['npm', 'PyPI', 'Maven']);
    expect(p.packages.npm).toEqual({ 'left-pad': [['CVE-2026-100001', 'GHSA-aaaa-bbbb-cccc', [['>=0', '<1.3.1']], ['0.0.0-x']]] });
    expect(Object.keys(p.packages.PyPI!)).toEqual(['django-foo']);
    expect(p.sources.map((s) => [s.ecosystem, s.ok, s.advisories, s.matched])).toEqual([
      ['npm', true, 2, 1], ['PyPI', true, 1, 1], ['Maven', true, 1, 1], ['Go', false, 0, 0],
      ['crates.io', false, 0, 0], ['RubyGems', false, 0, 0], ['Packagist', false, 0, 0], ['NuGet', false, 0, 0],
    ]);
    const index = new Map(read<RowTable>(PATHS.index).rows.map((r) => [r[0], JSON.stringify(r)]));
    expect(JSON.stringify(p.cves.rows[1])).toBe(index.get('CVE-2026-100001'));
  });

  it('checks every packages.json entry, its attribution and its rows', () => {
    const p = read<PackagesFile>(PATHS.packages);
    const check = (change: (f: PackagesFile) => void): string[] => {
      const f = structuredClone(p);
      change(f);
      write(PATHS.packages, f);
      return validateOutput(dir).errors.filter((e) => e.startsWith(PATHS.packages));
    };
    expect(check(() => {})).toEqual([]);
    expect(check((f) => void (f.packages.npm!['left-pad'][0][1] = 'OSV-2020-111'))[0]).toContain('OSV-2020-111 is from a database the attribution does not list');
    expect(check((f) => void (f.packages.npm!['left-pad'][0][2] = [['>=0', '< 1.3.1']]))[0]).toContain('has a malformed range');
    expect(check((f) => void (f.packages.npm!['left-pad'][0][3] = ['1.0\u0007']))[0]).toContain('has malformed versions');
    expect(check((f) => void (f.packages.PyPI = { Django_Foo: f.packages.PyPI!['django-foo'] }))[0]).toContain('is not in packageKey() form');
    expect(check((f) => void (f.attribution = f.attribution.filter((a) => !a.notice)))).toContain(`${PATHS.packages}: attribution does not match shared/packages.ts ATTRIBUTION`);
    expect(check((f) => void (f.packages.Go = { x: f.packages.npm!['left-pad'] }))).toContain(`${PATHS.packages}: packages has Go, which is not an ecosystem with a copy`);
    expect(check((f) => void (f.cves.rows[1][6] = 99))).toContain(`${PATHS.packages}: 1 cves rows differ from their index.json row (first: CVE-2026-100001)`);
    expect(check((f) => void f.cves.rows.pop())).toContain(`${PATHS.packages}: 1 CVEs named in packages have no row in cves (first: CVE-2026-100001)`);
    expect(check((f) => void ((f.packages.npm = {}), (f.packages.PyPI = {})))).toContain(`${PATHS.packages}: 1 cves rows are not named in packages (first: CVE-2026-100001)`);
    expect(check((f) => void (f.sources = f.sources.slice(1)))).toContain(`${PATHS.packages}: sources must list every ecosystem once, in PACKAGE_ECOSYSTEMS order`);
    unlinkSync(join(dir, PATHS.packages));
    expect(validateOutput(dir).errors).toContain(`missing ${PATHS.packages}`);
  });
});

describe('buildOutput', () => {
  it('scores with the sources that ingest reported down as unknown, not absent', () => {
    const build = (spec: Parameters<typeof makeIngest>[1]) =>
      buildOutput({ ingest: makeIngest([makeCve({ id: 'CVE-2026-100009' })], spec), now: NOW, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://example.test' })
        .scored[0];
    const up = build({});
    expect(up.reasons.map((r) => r.id)).toEqual(expect.arrayContaining(['prior.none', 'x.none']));
    const down = build({ down: ['kev', 'exploitdb'] });
    expect(down.reasons.map((r) => r.id)).toEqual(expect.arrayContaining(['prior.unknown', 'x.too_new']));
    expect(down.reasons.some((r) => r.id === 'prior.none' || r.id === 'x.none')).toBe(false);
    expect(down.unknowns).toContain('kev and exploitdb could not be loaded this run, so their evidence is unknown, not counted as absent.');
  });
});
