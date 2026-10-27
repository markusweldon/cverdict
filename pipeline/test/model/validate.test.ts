import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SCHEMA_VERSION, rowsFromTable, type CveShard, type Meta, type RowTable } from '../../../shared/contract';
import { shardOf } from '../../../shared/shard';
import { buildOutput } from '../../src/emit/build';
import { PATHS, SHARD_NAMES, writeFiles } from '../../src/emit/json';
import { formatSizeTable, validateOutput } from '../../src/validate';
import type { Logger } from '../../src/types';
import { NOW, cohort, makeCve, makeIngest, makeKev, msf } from '../fixtures/model/builders';

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
const built = buildOutput({ ingest: makeIngest(cves, spec), now: NOW, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://example.test' });

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
    expect(result.files).toBe(7 + SHARD_NAMES.length + 3);
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
    expect(validateOutput(dir).errors).toEqual([`1 index rows have no detail shard entry (first: ${id})`]);
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

  it('enforces the file count limit', () => {
    for (let i = 0; i < 40; i++) write(`v1/extra-${i}.txt`, 'x');
    expect(validateOutput(dir).errors).toContain(`${266 + 40} files emitted; the limit is 300`);
  });
});
