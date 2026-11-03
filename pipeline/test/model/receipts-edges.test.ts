/**
 * Edge cases of the Receipts forward log and backtest, written apart from the builder's tests:
 * gap totals past the kept list, listings a run can see but not record, UTC day maths, corrupt and
 * missing state, the retention boundary, KEV evidence in the backtest, and the receipts.json budget.
 */
import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { RECEIPT_METHODS, type ReceiptsFile } from '../../../shared/contract';
import { SCORE_MODEL } from '../../../shared/model';
import { evidenceAsOf, kevAsOf, runBacktest, SIGNALS, type BacktestInputs } from '../../src/backtest';
import { BUDGETS } from '../../src/config';
import { buildOutput } from '../../src/emit/build';
import { decodeLog, encodeLog, forwardReceipts, hourOf, LOG_RETENTION_DAYS, outcomeOf, updateLog, type ReceiptsLog } from '../../src/receipts';
import { toRow } from '../../src/rows';
import { buildKevPrior } from '../../src/score';
import { parseState } from '../../src/state';
import type { KevRaw, NormalizedCve } from '../../src/types';
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
  it('keeps receipts.json within budget with a year of forward listings next to a full backtest', () => {
    // ~25 KEV additions a month that we saw first, as many older ones, each with its row; 180 backtest CVEs.
    const rows = Array.from({ length: 600 }, (_, i) => {
      const id = `CVE-2026-${200000 + i}`;
      return toRow(score(makeCve({ id, published: T0.toISOString(), title: `Remote code execution in Example Product ${i} management console`, ...cvss(9.8) })));
    });
    const flag = { at: T0.toISOString(), outcome: 'earlier' as const, lead: 3 };
    const items = rows.slice(0, 300).map((row) => ({ id: row.id, kev_added: '2027-01-01', first_seen: T0.toISOString(), flags: { cverdict: flag, cvss7: flag, epss10: { at: null, outcome: 'never' as const, lead: null } }, row }));
    const uncounted = rows.slice(300).map((row) => ({ id: row.id, kev_added: '2027-01-01', reason: 'older' as const, row }));
    const no = { cverdict: false, cvss7: true, epss10: false };
    const btItems = rows.slice(0, 180).map((row) => ({ id: row.id, kev_added: '2026-10-01', published: T0.toISOString(), old: false, strict: no, upper: no, score: 50, chips: ['sev.crit_net', 'ssvc.total', 'prior.vendor'], cvss: 9.8, epss: 0.01, epss_date: '2026-09-30', left_out: ['ssvc', 'nuclei'], row }));
    const zero = RECEIPT_METHODS.map((method) => ({ method, n: 300, before: 0, earlier: 0, same_day: 0, lead: null }));
    const file = { forward: { items, uncounted, methods: zero }, backtest: { items: btItems } } as unknown as ReceiptsFile;
    const gz = gzipSync(JSON.stringify(file)).length;
    expect(gz).toBeLessThan(BUDGETS.gzipBytes['v1/receipts.json']);
  });
});
