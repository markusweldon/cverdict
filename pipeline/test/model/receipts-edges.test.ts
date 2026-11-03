/**
 * Edge cases of the Receipts forward log and backtest, written apart from the builder's tests:
 * gap totals past the kept list, listings a run can see but not record, UTC day maths, corrupt and
 * missing state, the retention boundary, KEV evidence in the backtest, and the receipts.json budget
 * over five years of listings.
 */
import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { RECEIPT_METHODS, type ReceiptsFile } from '../../../shared/contract';
import { SCORE_MODEL } from '../../../shared/model';
import { evidenceAsOf, kevAsOf, runBacktest, SIGNALS, type BacktestInputs } from '../../src/backtest';
import { BUDGETS } from '../../src/config';
import { buildOutput } from '../../src/emit/build';
import { decodeLog, encodeLog, forwardReceipts, hourOf, LOG_RETENTION_DAYS, outcomeOf, updateLog, type LogEntry, type ReceiptsLog } from '../../src/receipts';
import { toRow } from '../../src/rows';
import { buildKevPrior } from '../../src/score';
import { parseState } from '../../src/state';
import type { KevRaw, NormalizedCve } from '../../src/types';
import type { Row } from '../../../shared/contract';
import { cvss, makeCve, makeEnrichment, makeIngest, makeKev, makeKevCatalog, score, ssvc } from '../fixtures/model/builders';

const T0 = new Date('2026-11-03T03:17:00Z');
const at = (hours: number) => new Date(T0.getTime() + hours * 3_600_000);
const ymd = (d: Date) => d.toISOString().slice(0, 10);
const ID = 'CVE-2026-100001';
const windowCve = (id: string, when: Date, o: Partial<NormalizedCve> = {}) =>
  makeCve({ id, published: new Date(when.getTime() - 3_600_000).toISOString(), ...cvss(5.3), ...o });
const catalog = (entries: KevRaw[] = []) => makeKevCatalog(entries);

describe('forward log: gaps', () => {
  it('counts every gap and its hours, not only the 50 it keeps, and survives the state file', () => {
    let log: ReceiptsLog | null = null;
    for (let i = 0; i <= 60; i++) log = updateLog(log, [], catalog(), at(i * 5)).log;
    expect(log!.gaps).toHaveLength(50);
    expect(log!.gapTotal).toEqual({ n: 60, hours: 300 });
    const back = decodeLog(JSON.parse(JSON.stringify(encodeLog(log!))))!;
    expect(back.gapTotal).toEqual({ n: 60, hours: 300 });
    const f = forwardReceipts(back, catalog(), new Map(), at(300), 30);
    expect(f.gap_total).toEqual({ n: 60, hours: 300 });
    expect(f.gaps).toHaveLength(50);
  });

  it('reads a log written before gap_total existed by summing the gaps it kept', () => {
    let log: ReceiptsLog | null = null;
    for (const h of [0, 4, 4.5, 10]) log = updateLog(log, [], catalog(), at(h)).log;
    const encoded = encodeLog(log!) as unknown as Record<string, unknown>;
    delete encoded.gap_total;
    expect(decodeLog(encoded)!.gapTotal).toEqual({ n: 2, hours: 9.5 });
    // Fewer gaps in the total than in the list cannot be right: start a new log.
    expect(decodeLog({ ...encoded, gap_total: [1, 4] })).toBeNull();
    expect(decodeLog({ ...encoded, gap_total: ['x', 4] })).toBeNull();
  });
});

describe('forward log: listings and flags', () => {
  it('never credits CVErdict with a flag that came from a KEV listing it could not record', () => {
    // CISA-ADP KEV block without a date: CVErdict sees "exploited", the log cannot date the listing.
    const undated = score(windowCve(ID, T0, { adpKev: { dateAdded: null, reference: null } }));
    expect(undated.exploited).toBe(true);
    let log = updateLog(null, [undated], catalog(), T0).log;
    expect(log.entries.get(ID)!.flags.cverdict).toBeNull();
    // The catalog dates it the next day: the CVErdict flag comes with the listing, so it does not count.
    const listed = makeKev(ID, { dateAdded: ymd(at(24)) });
    log = updateLog(log, [score(windowCve(ID, T0), { kev: [listed] })], catalog([listed]), at(24)).log;
    const e = log.entries.get(ID)!;
    expect(e.kev).toEqual({ added: ymd(at(24)), seen: hourOf(at(24)) });
    expect(outcomeOf(e.flags.cverdict, e.kev!).outcome).toBe('after');
    // A catalog entry dated after the run (a frozen --now) is not a flag either.
    const future = makeKev('CVE-2026-100002', { dateAdded: ymd(at(72)) });
    const early = updateLog(null, [score(windowCve('CVE-2026-100002', T0), { kev: [future] })], catalog([future]), T0).log;
    expect(early.entries.get('CVE-2026-100002')!.flags.cverdict).toBeNull();
  });

  it('tells an older CVE from a KEV ID without a published record', () => {
    const log = updateLog(null, [], catalog(), T0).log;
    const old = makeKev('CVE-2019-0001', { dateAdded: ymd(at(24)) });
    const unpublished = makeKev('CVE-2026-999999', { dateAdded: ymd(at(24)) });
    const row = toRow(score(makeCve({ id: 'CVE-2019-0001', published: '2019-01-01T00:00:00Z', inWindow: false })));
    const f = forwardReceipts(log, catalog([old, unpublished]), new Map([[row.id, row]]), at(30), 30);
    expect(f.uncounted.map((u) => [u.id, u.reason])).toEqual([
      ['CVE-2019-0001', 'older'],
      ['CVE-2026-999999', 'no_record'],
    ]);
    expect(f.listed).toBe(2);
  });

  it('measures lead time in whole UTC days, whatever the hour of the flag', () => {
    const kev = { added: '2026-11-05', seen: hourOf(new Date('2026-11-05T18:00:00Z')) };
    // Flagged 23:00 UTC on the 3rd and 00:00 UTC on the 4th: 2 and 1 days.
    expect(outcomeOf(hourOf(new Date('2026-11-03T23:59:00Z')), kev)).toMatchObject({ outcome: 'earlier', lead: 2 });
    expect(outcomeOf(hourOf(new Date('2026-11-04T00:00:00Z')), kev)).toMatchObject({ outcome: 'earlier', lead: 1 });
    // On the listing day, by a run before the one that saw it: 0 days, apart from earlier.
    expect(outcomeOf(hourOf(new Date('2026-11-05T17:59:00Z')), kev)).toMatchObject({ outcome: 'same_day', lead: 0 });
    // In the run that saw the listing, or after the listing day, even before that run: after.
    expect(outcomeOf(kev.seen, kev).outcome).toBe('after');
    expect(outcomeOf(hourOf(new Date('2026-11-06T01:00:00Z')), { added: '2026-11-05', seen: hourOf(new Date('2026-11-06T09:00:00Z')) })).toMatchObject({ outcome: 'after', lead: null });
  });

  it('keeps an entry seen exactly 400 days ago and prunes it an hour later', () => {
    const log = updateLog(null, [score(windowCve(ID, T0, cvss(9.8)))], catalog(), T0).log;
    const edge = at(LOG_RETENTION_DAYS * 24);
    expect(updateLog(log, [], catalog(), edge).log.entries.has(ID)).toBe(true);
    const pruned = updateLog(log, [], catalog(), at(LOG_RETENTION_DAYS * 24 + 1)).log;
    expect(pruned.entries.has(ID)).toBe(false);
    expect(pruned.pruned).toEqual({ n: 1, cverdict: 0, cvss7: 1, epss10: 0 });
  });
});

describe('forward log: state', () => {
  const build = (now: Date, cves: NormalizedCve[], state?: ReturnType<typeof parseState>) =>
    buildOutput({ ingest: makeIngest(cves), now, windowDays: 30, knob: 50, previous: null, previousState: state, siteUrl: 'https://x.test' });

  it('starts a new log with a new since on a missing, corrupt or foreign previous state, and invents nothing', () => {
    const first = build(T0, [windowCve(ID, T0)]);
    const good = parseState(first.files.get('v1/state.json')!);
    for (const state of [undefined, parseState('{not json'), parseState('{"schema_version":1,"state_version":2,"generated_at":"2026-11-03T00:00:00Z","sections":{}}')]) {
      const r = build(at(5), [windowCve(ID, T0)], state).receipts.forward;
      expect(r).toMatchObject({ since: at(5).toISOString(), runs: 1, gaps: [], gap_total: { n: 0, hours: 0 }, eligible: 0 });
    }
    // A receipts section that is not understood: the rest of the state is used, the log starts again.
    const doc = JSON.parse(first.files.get('v1/state.json')!);
    doc.sections.receipts.data.ids = 'garbage';
    const r = build(at(5), [windowCve(ID, T0)], parseState(JSON.stringify(doc)));
    expect(r.receipts.forward.since).toBe(at(5).toISOString());
    expect(build(at(5), [windowCve(ID, T0)], good).receipts.forward).toMatchObject({ since: T0.toISOString(), runs: 2, gap_total: { n: 1, hours: 5 } });
  });
});

describe('backtest: evidence', () => {
  const LISTED = '2026-10-20';
  const cutoff = Date.parse(`${LISTED}T00:00:00Z`);
  const days = (n: number) => new Date(cutoff + n * 86_400_000).toISOString();

  it('never sees the listing, the CISA-ADP KEV block, or same-day listings of the vendor', () => {
    const k = makeKev(ID, { dateAdded: LISTED, vendorProject: 'Acme', product: 'Gateway' });
    const sameDay = makeKev('CVE-2026-100009', { dateAdded: LISTED, vendorProject: 'Acme', product: 'Gateway' });
    const enr = makeEnrichment({ kev: [k, sameDay] });
    const asOf = kevAsOf(enr.kev, LISTED);
    expect(asOf.entries.size).toBe(0);
    const cve = makeCve({ id: ID, published: days(-40), cnaUpdated: days(-39), adpKev: { dateAdded: LISTED, reference: null }, affected: [{ vendor: 'Acme', product: 'Gateway', versions: [] } as never] });
    for (const variant of ['strict', 'upper'] as const) {
      const e = evidenceAsOf({ cve, kev: k, enr, kevAsOf: { catalog: asOf, prior: buildKevPrior(asOf) }, epss: null, metasploitModified: new Map(), exploitdbAdded: new Map() }, variant);
      expect(e.cve.adpKev).toBeNull();
      expect(e.enr.kev.entries.has(ID)).toBe(false);
      expect(e.enr.prior.vendors.size).toBe(0);
    }
  });

  it('records the score model, lists the text it reads as it is today, and leaves out a day-before SSVC stamp', () => {
    const k = makeKev(ID, { dateAdded: LISTED });
    const cve = makeCve({ id: ID, published: days(-40), cnaUpdated: days(-39), adpUpdated: days(1), ssvc: ssvc('active', 'yes', 'total', days(-1)), ...cvss(9.8) });
    const enr = makeEnrichment({ kev: [k] });
    const s = score(cve, { kev: [k] });
    const inputs: BacktestInputs = { epss: new Map([[ymd(new Date(cutoff - 1)), new Map()]]), reuse: new Map(), metasploitModified: new Map(), exploitdbAdded: new Map(), volumeFrom: days(-200) };
    const b = runBacktest({ now: new Date(days(10)), kev: enr.kev, cves: new Map([[ID, cve]]), enr, inputs, scored: [s], rows: new Map([[ID, toRow(s)]]) });
    expect(b.score_model).toBe(SCORE_MODEL);
    expect(b.items[0].left_out).toContain('ssvc');
    expect(b.signals.find((x) => x.key === 'record_text')).toMatchObject({ treatment: 'today', affected: 1 });
    expect(SIGNALS.every((x) => ['time_matched', 'hindsight', 'excluded', 'today'].includes(x.treatment))).toBe(true);
  });
});

describe('budgets', () => {
  // A small seeded generator, so the rows read like real ones and do not compress unrealistically well.
  const words = 'remote code execution privilege escalation authentication bypass path traversal deserialization buffer overflow management console gateway firewall router appliance server portal plugin agent controller endpoint web interface allows unauthenticated attackers to execute arbitrary commands via crafted request in the of with'.split(' ');
  let seed = 7;
  const rnd = (n: number) => ((seed = (seed * 1103515245 + 12345) % 2 ** 31), seed % n);
  const text = (n: number) => Array.from({ length: n }, () => words[rnd(words.length)]).join(' ');
  const name = () => Array.from({ length: 2 + rnd(6) }, () => String.fromCharCode(97 + rnd(26))).join('');
  const realRow = (id: string, published: string) =>
    toRow(score(makeCve({ id, published, title: text(22), description: text(40), cna: name(), affected: [{ vendor: name(), product: `${name()} ${name()}`, purl: null }], ...cvss(5 + rnd(50) / 10) })));

  it('keeps receipts.json within budget after five years of forward listings next to a full backtest', () => {
    // ~350 KEV additions a year (the 2026 rate), 40% of them CVEs the log saw first, each with a row.
    const now = new Date(T0.getTime() + 5 * 365 * 86_400_000);
    const entries = new Map<string, LogEntry>();
    const kevs: KevRaw[] = [];
    const rows = new Map<string, Row>();
    for (let i = 0; i < 1750; i++) {
      const id = `CVE-2026-${200000 + i * 7}`;
      const added = ymd(new Date(T0.getTime() + Math.floor((i * 5 * 365) / 1750) * 86_400_000 + 86_400_000));
      const seen = hourOf(T0) + i * 25;
      kevs.push(makeKev(id, { dateAdded: added }));
      rows.set(id, realRow(id, new Date(seen * 3_600_000).toISOString()));
      if (i % 10 < 4) entries.set(id, { seen, flags: { cverdict: i % 3 ? seen + 2 : null, cvss7: seen, epss10: i % 2 ? null : seen + 30 }, kev: { added, seen: hourOf(`${added}T20:00:00Z`) } });
    }
    const log: ReceiptsLog = { since: T0.toISOString(), last: now.toISOString(), runs: 40_000, gaps: [], gapTotal: { n: 0, hours: 0 }, entries, pruned: { n: 900_000, cverdict: 9000, cvss7: 400_000, epss10: 3000 } };
    const forward = forwardReceipts(log, catalog(kevs), rows, now, 30);
    expect(forward.listed).toBe(1750);
    // Rows only on listings of the last year; none on uncounted listings.
    const yearAgo = ymd(new Date(now.getTime() - 365 * 86_400_000));
    expect(forward.items.every((it) => (it.row !== null) === (it.kev_added >= yearAgo))).toBe(true);
    expect(forward.items.some((it) => it.row !== null)).toBe(true);
    expect(forward.uncounted.every((u) => !('row' in u))).toBe(true);
    const no = { cverdict: false, cvss7: true, epss10: false };
    const btItems = [...rows.values()].slice(0, 180).map((row) => ({ id: row.id, kev_added: '2026-10-01', published: T0.toISOString(), old: false, strict: no, upper: no, score: 50, chips: ['sev.crit_net', 'ssvc.total', 'prior.vendor'], cvss: 9.8, epss: 0.01, epss_date: '2026-09-30', left_out: ['ssvc', 'nuclei'], row }));
    const file = { schema_version: 1, forward, backtest: { items: btItems } } as unknown as ReceiptsFile;
    const gz = gzipSync(JSON.stringify(file)).length;
    expect(gz).toBeLessThan(BUDGETS.gzipBytes['v1/receipts.json']);
  });
});
