import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import type { ReceiptMethod } from '../../../shared/contract';
import { BUDGETS } from '../../src/config';
import { buildOutput } from '../../src/emit/build';
import {
  decodeIds,
  decodeLog,
  encodeIds,
  encodeLog,
  forwardReceipts,
  hourOf,
  isEligible,
  leadDays,
  LOG_RETENTION_DAYS,
  outcomeOf,
  quantile,
  RECEIPTS_SECTION,
  sortedIds,
  updateLog,
  type LogEntry,
  type ReceiptsLog,
} from '../../src/receipts';
import { parseState, readSection, serializeState } from '../../src/state';
import type { KevRaw, NormalizedCve } from '../../src/types';
import { cvss, makeCve, makeIngest, makeKev, makeKevCatalog, score } from '../fixtures/model/builders';

const T0 = new Date('2026-11-03T03:17:00Z');
const later = (hours: number) => new Date(T0.getTime() + hours * 3_600_000);
const ymd = (d: Date) => d.toISOString().slice(0, 10);

/** A window CVE published an hour before `at`, scored at `at`. */
function cveAt(id: string, at: Date, o: Partial<NormalizedCve> = {}): NormalizedCve {
  return makeCve({ id, published: new Date(at.getTime() - 3_600_000).toISOString(), ...cvss(5.3), ...o });
}
const quiet = (id: string, at: Date) => score(cveAt(id, at), {}, undefined);
const kev = (entries: KevRaw[] = []) => makeKevCatalog(entries);

/** Run updateLog over a sequence of runs; each run gives the scored records and KEV entries. */
function runs(steps: { at: Date; scored: ReturnType<typeof score>[]; kev?: KevRaw[] }[], start: ReceiptsLog | null = null): ReceiptsLog {
  let log = start;
  for (const s of steps) log = updateLog(log, s.scored, kev(s.kev), s.at).log;
  return log!;
}

describe('log encoding', () => {
  it('round-trips ids across years, gaps and short sequence numbers', () => {
    const ids = sortedIds(['CVE-2026-104596', 'CVE-2025-0001', 'CVE-2026-0009', 'CVE-2026-104597', 'CVE-2026-0322', 'CVE-2024-123456']);
    expect(ids).toEqual(['CVE-2024-123456', 'CVE-2025-0001', 'CVE-2026-0009', 'CVE-2026-0322', 'CVE-2026-104596', 'CVE-2026-104597']);
    expect(encodeIds(ids)).toBe('2024:123456 2025:1 2026:9,313,104274,1');
    expect(decodeIds(encodeIds(ids))).toEqual(ids);
  });

  it('rejects ids that are unsorted, duplicated or malformed', () => {
    expect(decodeIds('2026:5,0')).toBeNull();
    expect(decodeIds('2026:5 2025:1')).toBeNull();
    expect(decodeIds('2026:x')).toBeNull();
    expect(decodeIds('')).toEqual([]);
  });

  it('round-trips a log through the state file', () => {
    const log = runs([
      { at: T0, scored: [quiet('CVE-2026-100001', T0), score(cveAt('CVE-2026-100002', T0, cvss(9.8)), {})] },
      { at: later(1), scored: [quiet('CVE-2026-100001', later(1)), score(cveAt('CVE-2026-100002', later(1), cvss(9.8)), { epss: { 'CVE-2026-100002': [0.3, 0.99] } })] },
    ]);
    const text = serializeState(later(1), [{ key: RECEIPTS_SECTION.key, version: RECEIPTS_SECTION.version, data: encodeLog(log) }]);
    const back = readSection(parseState(text), RECEIPTS_SECTION);
    expect(back).toEqual(log);
  });

  it('starts a new log from corrupt data instead of guessing', () => {
    const good = encodeLog(runs([{ at: T0, scored: [quiet('CVE-2026-100001', T0)] }]));
    expect(decodeLog(good)).not.toBeNull();
    expect(decodeLog({ ...good, seen: '0,0' })).toBeNull(); // column length differs from ids
    expect(decodeLog({ ...good, cverdict: 'x' })).toBeNull();
    expect(decodeLog({ ...good, h0: good.h0 + 1 })).toBeNull();
    expect(decodeLog({ ...good, kev: { 'CVE-2026-999999': ['2026-11-03', 0] } })).toBeNull(); // listing for a CVE not in the log
    expect(decodeLog({ ...good, pruned: { n: -1 } })).toBeNull();
    expect(decodeLog('junk')).toBeNull();
    expect(readSection(parseState('{"schema_version":1'), RECEIPTS_SECTION)).toBeNull();
  });

  it('keeps a 400-day log of 200,000 CVEs within the state.json budget', () => {
    // Realistic shape: ~520 new CVEs an hour-ish, spread over 400 days; half cross CVSS 7 on the
    // first run, 2% are flagged within the window, 0.2% cross EPSS 10% after a few days.
    const entries = new Map<string, LogEntry>();
    const h0 = hourOf(T0);
    let seq = 10000;
    let state = 12345;
    const rand = () => ((state = (state * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
    for (let i = 0; i < 200_000; i++) {
      seq += 1 + Math.floor(rand() * 3);
      const seen = h0 + Math.floor((i / 200_000) * LOG_RETENTION_DAYS * 24 + rand() * 6);
      const r = rand();
      entries.set(`CVE-${seq > 190000 ? 2027 : 2026}-${seq}`, {
        seen,
        flags: { cverdict: r < 0.02 ? seen + Math.floor(rand() * 400) : null, cvss7: r < 0.5 ? seen + (rand() < 0.9 ? 0 : 30) : null, epss10: r < 0.002 ? seen + 400 : null },
        kev: null,
      });
    }
    const log: ReceiptsLog = { since: T0.toISOString(), last: T0.toISOString(), runs: 9600, gaps: [], entries, pruned: { n: 0, cverdict: 0, cvss7: 0, epss10: 0 } };
    const gz = gzipSync(JSON.stringify(encodeLog(log))).length;
    // Woke tracking uses ~25 KB of the same file.
    expect(gz + 30 * 1024).toBeLessThan(BUDGETS.gzipBytes['v1/state.json']);
    expect(decodeLog(JSON.parse(JSON.stringify(encodeLog(log))))!.entries.size).toBe(200_000);
  });
});

describe('updateLog', () => {
  it('starts a log on a missing previous, with since = this run, and never back-dates', () => {
    const { log, updated, notes } = updateLog(null, [quiet('CVE-2026-100001', T0)], kev(), T0);
    expect(updated).toBe(true);
    expect(log.since).toBe(T0.toISOString());
    expect(log.runs).toBe(1);
    expect(log.entries.get('CVE-2026-100001')).toEqual({ seen: hourOf(T0), flags: { cverdict: null, cvss7: null, epss10: null }, kev: null });
    expect(notes[0]).toMatch(/new log starts now/);
  });

  it('records the first flag of each method once, and only while the CVE is in the window', () => {
    const id = 'CVE-2026-100001';
    const hot = (at: Date) => score(cveAt(id, at, cvss(9.8)), { epss: { [id]: [0.4, 0.99] }, kev: [] });
    const log = runs([
      { at: T0, scored: [quiet(id, T0)] },
      { at: later(1), scored: [score(cveAt(id, later(1), cvss(9.8)), {})] },
      { at: later(2), scored: [hot(later(2))] },
      { at: later(3), scored: [quiet(id, later(3))] },
      { at: later(4), scored: [hot(later(4))] },
    ]);
    const e = log.entries.get(id)!;
    expect(e.seen).toBe(hourOf(T0));
    expect(e.flags.cvss7).toBe(hourOf(later(1)));
    expect(e.flags.epss10).toBe(hourOf(later(2)));
    // CVSS 9.8 network + EPSS 40% (cold, so no EPSS points) is still below the knob: not flagged.
    expect(e.flags.cverdict).toBeNull();

    // Outside the window: no new entry, and no new flag for an existing one.
    const outside = score(cveAt('CVE-2026-100009', later(5), { inWindow: false, ...cvss(9.8) }), {});
    const next = updateLog(log, [outside, score(cveAt(id, later(5), { inWindow: false }), { kev: [makeKev(id, { dateAdded: ymd(later(5)) })] })], kev(), later(5)).log;
    expect(next.entries.has('CVE-2026-100009')).toBe(false);
    expect(next.entries.get(id)!.flags.cverdict).toBeNull();
  });

  it('records a CVErdict flag at the run where the tier first passes', () => {
    const id = 'CVE-2026-100001';
    const flaggedNow = score(cveAt(id, later(2)), { metasploit: { [id]: [{ name: 'x', fullname: 'exploit/x', rank: 600, type: 'exploit', url: 'https://x.test', date: null }] } });
    expect(flaggedNow.tier).toBe('likely');
    const log = runs([
      { at: T0, scored: [quiet(id, T0)] },
      { at: later(2), scored: [flaggedNow] },
    ]);
    expect(log.entries.get(id)!.flags.cverdict).toBe(hourOf(later(2)));
  });

  it('records KEV arrival with the run that first saw it, at any age, from the catalog or the CVE record', () => {
    const a = 'CVE-2026-100001';
    const b = 'CVE-2026-100002';
    let log = runs([{ at: T0, scored: [quiet(a, T0), quiet(b, T0)] }]);
    log = updateLog(log, [], kev([makeKev(a, { dateAdded: ymd(later(30)) })]), later(30)).log;
    expect(log.entries.get(a)!.kev).toEqual({ added: ymd(later(30)), seen: hourOf(later(30)) });
    // A later run with the same listing does not move it.
    log = updateLog(log, [], kev([makeKev(a, { dateAdded: ymd(later(30)) })]), later(31)).log;
    expect(log.entries.get(a)!.kev!.seen).toBe(hourOf(later(30)));
    // No catalog, but the CISA-ADP KEV block in the record.
    const adp = score(cveAt(b, later(32), { inWindow: true, adpKev: { dateAdded: ymd(later(32)), reference: null } }), {});
    log = updateLog(log, [adp], kev(), later(32)).log;
    expect(log.entries.get(b)!.kev).toEqual({ added: ymd(later(32)), seen: hourOf(later(32)) });
  });

  it('ignores KEV entries dated after the run (a frozen --now)', () => {
    const a = 'CVE-2026-100001';
    const log = updateLog(runs([{ at: T0, scored: [quiet(a, T0)] }]), [], kev([makeKev(a, { dateAdded: ymd(later(48)) })]), later(1)).log;
    expect(log.entries.get(a)!.kev).toBeNull();
  });

  it('records gaps, and carries the log over unchanged when the clock is behind it', () => {
    const log = runs([
      { at: T0, scored: [] },
      { at: later(10), scored: [] },
    ]);
    expect(log.gaps).toEqual([[T0.toISOString(), later(10).toISOString()]]);
    const back = updateLog(log, [quiet('CVE-2026-100001', later(5))], kev(), later(5));
    expect(back.updated).toBe(false);
    expect(back.log).toBe(log);
  });

  it('prunes entries without a listing after 400 days, keeps their counts, and keeps entries with one', () => {
    const a = 'CVE-2026-100001';
    const b = 'CVE-2026-100002';
    let log = runs([{ at: T0, scored: [score(cveAt(a, T0, cvss(9.8)), {}), quiet(b, T0)] }]);
    log = updateLog(log, [], kev([makeKev(b, { dateAdded: ymd(later(24 * 100)) })]), later(24 * 100)).log;
    log = updateLog(log, [], kev(), later(24 * (LOG_RETENTION_DAYS + 1))).log;
    expect(log.entries.has(a)).toBe(false);
    expect(log.entries.has(b)).toBe(true);
    expect(log.pruned).toEqual({ n: 1, cverdict: 0, cvss7: 1, epss10: 0 });
    const f = forwardReceipts(log, kev(), new Map(), later(24 * (LOG_RETENTION_DAYS + 1)), 30);
    expect(f.volume.find((v) => v.method === 'cvss7')).toEqual({ method: 'cvss7', n: 2, flagged: 1 });
  });
});

describe('outcomes and metrics', () => {
  const H = hourOf(new Date('2026-11-10T14:00:00Z'));
  const listing = { added: '2026-11-10', seen: H };

  it('sorts a flag into earlier, same day, after or never', () => {
    expect(outcomeOf(null, listing)).toEqual({ at: null, outcome: 'never', lead: null });
    expect(outcomeOf(H - 24 * 3, listing)).toMatchObject({ outcome: 'earlier', lead: 3 });
    // Earlier on the listing day, before the run that saw the listing: same day, 0 days.
    expect(outcomeOf(H - 5, listing)).toMatchObject({ outcome: 'same_day', lead: 0 });
    // The run that saw the listing (the flag came with it) or later: not before.
    expect(outcomeOf(H, listing)).toMatchObject({ outcome: 'after', lead: null });
    expect(outcomeOf(H + 5, listing)).toMatchObject({ outcome: 'after' });
    // Before the run that saw the listing, but after the KEV date (we saw the catalog late): not before.
    const late = { added: '2026-11-09', seen: H };
    expect(outcomeOf(H - 2, late)).toMatchObject({ outcome: 'after' });
  });

  it('computes medians and quartiles by linear interpolation', () => {
    expect(quantile([5], 0.5)).toBe(5);
    expect(quantile([1, 2, 3, 4], 0.5)).toBe(2.5);
    expect(quantile([1, 2, 3, 4], 0.25)).toBe(1.8);
    expect(quantile([1, 2, 3, 4], 0.75)).toBe(3.3);
    expect(leadDays([0, 10, 2, 40, 7])).toEqual({ median: 7, q1: 2, q3: 10 });
    expect(leadDays([])).toBeNull();
    expect(() => quantile([], 0.5)).toThrow();
  });

  it('counts a listing only when the CVE was seen by an earlier run, on or before the listing day', () => {
    const e = (seen: number, kevSeen: number, added = '2026-11-10'): LogEntry => ({ seen, flags: { cverdict: null, cvss7: null, epss10: null }, kev: { added, seen: kevSeen } });
    expect(isEligible(e(H - 48, H))).toBe(true);
    expect(isEligible(e(H, H))).toBe(false); // the CVE and its listing arrived in the same run
    expect(isEligible(e(H - 1, H, '2026-11-09'))).toBe(false); // seen only after the KEV date
  });

  it('builds the forward figures with the same definitions for every method, misses included', () => {
    const ids = ['CVE-2026-100001', 'CVE-2026-100002', 'CVE-2026-100003', 'CVE-2026-100004'];
    const at = (iso: string) => hourOf(new Date(iso));
    const flags = (c: number | null, v: number | null, e: number | null): Record<ReceiptMethod, number | null> => ({ cverdict: c, cvss7: v, epss10: e });
    const entries = new Map<string, LogEntry>([
      // Flagged by CVErdict 4 days early, CVSS at first sight, EPSS never.
      [ids[0], { seen: at('2026-11-03T03:00:00Z'), flags: flags(at('2026-11-06T03:00:00Z'), at('2026-11-03T03:00:00Z'), null), kev: { added: '2026-11-10', seen: at('2026-11-10T15:00:00Z') } }],
      // Flagged by CVErdict only with the listing; CVSS same day before it.
      [ids[1], { seen: at('2026-11-03T03:00:00Z'), flags: flags(at('2026-11-12T15:00:00Z'), at('2026-11-12T09:00:00Z'), null), kev: { added: '2026-11-12', seen: at('2026-11-12T15:00:00Z') } }],
      // Published and listed in the same run: not counted.
      [ids[2], { seen: at('2026-11-12T15:00:00Z'), flags: flags(at('2026-11-12T15:00:00Z'), null, null), kev: { added: '2026-11-12', seen: at('2026-11-12T15:00:00Z') } }],
      // Never listed.
      [ids[3], { seen: at('2026-11-03T03:00:00Z'), flags: flags(null, null, at('2026-11-05T03:00:00Z')), kev: null }],
    ]);
    const log: ReceiptsLog = { since: '2026-11-03T03:17:00.000Z', last: '2026-11-13T00:17:00.000Z', runs: 200, gaps: [], entries, pruned: { n: 0, cverdict: 0, cvss7: 0, epss10: 0 } };
    // An old CVE listed since the log started, and one listed before it started (left out).
    const catalog = kev([makeKev('CVE-2019-0001', { dateAdded: '2026-11-05' }), makeKev('CVE-2018-0001', { dateAdded: '2026-11-01' })]);
    const f = forwardReceipts(log, catalog, new Map(), new Date('2026-11-13T00:17:00Z'), 30);
    expect(f.listed).toBe(4);
    expect(f.eligible).toBe(2);
    expect(f.uncounted.map((u) => [u.id, u.reason])).toEqual([
      ['CVE-2026-100003', 'listed_first'],
      ['CVE-2019-0001', 'older'],
    ]);
    expect(f.items.map((i) => i.id)).toEqual([ids[1], ids[0]]);
    const m = Object.fromEntries(f.methods.map((x) => [x.method, x]));
    expect(m.cverdict).toEqual({ method: 'cverdict', n: 2, before: 1, earlier: 1, same_day: 0, lead: { median: 4, q1: 4, q3: 4 } });
    expect(m.cvss7).toEqual({ method: 'cvss7', n: 2, before: 2, earlier: 1, same_day: 1, lead: { median: 3.5, q1: 1.8, q3: 5.3 } });
    expect(m.epss10).toEqual({ method: 'epss10', n: 2, before: 0, earlier: 0, same_day: 0, lead: null });
    expect(f.items[0].flags.cverdict.outcome).toBe('after');
    expect(f.volume).toEqual([
      { method: 'cverdict', n: 4, flagged: 3 },
      { method: 'cvss7', n: 4, flagged: 2 },
      { method: 'epss10', n: 4, flagged: 1 },
    ]);
  });
});

describe('receipts.json from buildOutput', () => {
  it('carries the log across runs through state.json, and publishes since, n and the lists', () => {
    const id = 'CVE-2026-100001';
    const first = buildOutput({ ingest: makeIngest([cveAt(id, T0)]), now: T0, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://x.test' });
    expect(first.receipts.forward.since).toBe(T0.toISOString());
    expect(first.receipts.backtest).toBeNull();
    const state = parseState(first.files.get('v1/state.json')!);
    const second = buildOutput({
      ingest: makeIngest([cveAt(id, later(24))], { kev: [makeKev(id, { dateAdded: ymd(later(24)) })] }),
      now: later(24),
      windowDays: 30,
      knob: 50,
      previous: null,
      previousState: state,
      siteUrl: 'https://x.test',
    });
    const f = second.receipts.forward;
    expect(f.since).toBe(T0.toISOString());
    expect(f.runs).toBe(2);
    expect(f.gaps).toHaveLength(1);
    expect(f.eligible).toBe(1);
    // Seen the day before; flagged only by the listing itself, so not before it.
    expect(f.items[0]).toMatchObject({ id, kev_added: ymd(later(24)), flags: { cverdict: { outcome: 'after' }, cvss7: { outcome: 'never' }, epss10: { outcome: 'never' } } });
    expect(f.items[0].row?.id).toBe(id);
    expect(JSON.parse(second.files.get('v1/receipts.json')!).forward.items[0].id).toBe(id);
  });
});
