import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RECEIPT_METHODS, type BacktestReceipts } from '../../../shared/contract';
import { SCORE_MODEL } from '../../../shared/model';
import {
  BACKTEST_REFRESH_DAYS,
  backtestProblems,
  decideBacktest,
  evidenceAsOf,
  kevAsOf,
  readPreviousBacktest,
  runBacktest,
  type AsOfInput,
  type BacktestInputs,
} from '../../src/backtest';
import { buildOutput } from '../../src/emit/build';
import { buildKevPrior, scoreCve } from '../../src/score';
import type { NormalizedCve } from '../../src/types';
import { cvss, edb, makeCve, makeEnrichment, makeIngest, makeKev, makeKevCatalog, msf, nucleiTemplate, repo, ssvc, type EnrichmentSpec } from '../fixtures/model/builders';

const NOW = new Date('2026-11-03T03:17:00Z');
const ID = 'CVE-2026-100001';
const LISTED = '2026-10-20';
const CUTOFF = '2026-10-20T00:00:00.000Z';
const before = (days: number) => new Date(Date.parse(CUTOFF) - days * 86_400_000).toISOString();
const after = (days: number) => new Date(Date.parse(CUTOFF) + days * 86_400_000).toISOString();

/** A CVE published 30 days before its KEV listing, with a CNA record unchanged since. */
function kevCve(o: Partial<NormalizedCve> = {}): NormalizedCve {
  return makeCve({ id: ID, published: before(30), cnaUpdated: before(29), inWindow: false, ...o });
}

function asOf(cve: NormalizedCve, spec: EnrichmentSpec = {}, o: Partial<AsOfInput> = {}): AsOfInput {
  const k = makeKev(ID, { dateAdded: LISTED });
  const enr = makeEnrichment({ kev: [k, ...(spec.kev ?? [])], ...spec });
  const catalog = kevAsOf(enr.kev, LISTED);
  return { cve, kev: k, enr, kevAsOf: { catalog, prior: buildKevPrior(catalog) }, epss: { date: '2026-10-19', score: null }, metasploitModified: new Map(), exploitdbAdded: new Map(), ...o };
}

const scoreOf = (input: AsOfInput, variant: 'strict' | 'upper') => {
  const e = evidenceAsOf(input, variant);
  return { ...scoreCve(e.cve, e.enr, { now: new Date(CUTOFF) }), leftOut: e.leftOut, evidence: e };
};

describe('evidence as of the day before the listing', () => {
  it('never uses the KEV listing or the CISA-ADP KEV block, and only earlier listings for the prior', () => {
    const input = asOf(kevCve({ adpKev: { dateAdded: LISTED, reference: null } }), {
      kev: [makeKev('CVE-2026-100002', { dateAdded: '2026-10-01' }), makeKev('CVE-2026-100003', { dateAdded: LISTED }), makeKev('CVE-2026-100004', { dateAdded: '2026-10-25' })],
    });
    for (const variant of ['strict', 'upper'] as const) {
      const s = scoreOf(input, variant);
      expect(s.exploited).toBe(false);
      expect(s.reasons.some((r) => r.id === 'kev.listed')).toBe(false);
      expect(s.evidence.cve.adpKev).toBeNull();
      expect([...s.evidence.enr.kev.entries.keys()]).toEqual(['CVE-2026-100002']);
      // One other Acme Widget listing before the cutoff: the product prior, from the as-of catalog.
      expect(s.reasons.find((r) => r.family === 'PRIOR')?.label).toMatch(/×1/);
    }
  });

  it('uses the EPSS score of the day before only, and leaves EPSS out when that file is missing', () => {
    const withEpss = scoreOf(asOf(kevCve(), { epss: { [ID]: [0.9, 0.99] } }, { epss: { date: '2026-10-19', score: 0.2 } }), 'strict');
    expect(withEpss.reasons.find((r) => r.id === 'epss.high')).toBeTruthy();
    expect(withEpss.epss?.score).toBe(0.2); // not today's 0.9
    const noFile = scoreOf(asOf(kevCve(), { epss: { [ID]: [0.9, 0.99] } }, { epss: null }), 'upper');
    expect(noFile.epss).toBeNull();
    expect(noFile.reasons.find((r) => r.id === 'x.none')).toBeUndefined(); // unknown, not absent
  });

  it('keeps Exploit-DB entries added before the listing day, by date_added', () => {
    const input = asOf(kevCve(), { exploitdb: { [ID]: [edb('5001', '2026-10-01'), edb('5002', '2026-10-01')] } }, { exploitdbAdded: new Map([['5001', '2026-10-25'], ['5002', '2026-10-19']]) });
    const e = evidenceAsOf(input, 'strict');
    expect(e.enr.exploits.exploitdb.get(ID)?.map((x) => x.id)).toEqual(['5002']);
    const none = evidenceAsOf(asOf(kevCve(), { exploitdb: { [ID]: [edb('5001', '2026-10-20')] } }), 'upper');
    expect(none.enr.exploits.exploitdb.has(ID)).toBe(false);
  });

  it('keeps PoC repos created before the cutoff; strict vets them by age only', () => {
    const repos = [repo(before(1), 50, false, 'starred-new'), repo(after(1), 99, false, 'later')];
    const strict = scoreOf(asOf(kevCve(), { poc: { [ID]: repos } }), 'strict');
    expect(strict.evidence.enr.exploits.poc.get(ID)?.map((r) => r.url)).toEqual(['https://github.com/someone/starred-new']);
    expect(strict.exploits.poc.vetted).toBe(0); // 1 day old at the cutoff; today's stars ignored
    expect(strict.leftOut).toContain('poc_stars');
    const upper = scoreOf(asOf(kevCve(), { poc: { [ID]: repos } }), 'upper');
    expect(upper.exploits.poc.vetted).toBe(1);
  });

  it('strictly counts a PoC repo only when its last push is before the cutoff too; upper counts it anyway', () => {
    // Listed later than it was created, pushed after the listing: its code may postdate the listing.
    const late = [repo(before(30), 0, false, 'pushed-later', after(1))];
    const strict = scoreOf(asOf(kevCve(), { poc: { [ID]: late } }), 'strict');
    expect(strict.evidence.enr.exploits.poc.has(ID)).toBe(false);
    expect(strict.leftOut).toContain('poc_content');
    expect(strict.reasons.some((r) => r.id === 'x.poc')).toBe(false);
    const upper = scoreOf(asOf(kevCve(), { poc: { [ID]: late } }), 'upper');
    expect(upper.exploits.poc.vetted).toBe(1);
    expect(upper.leftOut).not.toContain('poc_content');
    // No push time at all: unknown, so the same.
    expect(scoreOf(asOf(kevCve(), { poc: { [ID]: [repo(before(30), 0, false, 'x', null)] } }), 'strict').leftOut).toContain('poc_content');
    // Pushed before the cutoff: dated.
    const dated = scoreOf(asOf(kevCve(), { poc: { [ID]: [repo(before(30), 0, false, 'x', before(2))] } }), 'strict');
    expect(dated.exploits.poc.vetted).toBe(1);
    expect(dated.leftOut).not.toContain('poc_content');
  });

  it('counts a Metasploit module modified before the cutoff; otherwise strict leaves it out as unknown', () => {
    const spec = { metasploit: { [ID]: [msf('exploit/linux/http/acme')] } };
    const dated = scoreOf(asOf(kevCve(), spec, { metasploitModified: new Map([[ID, before(3)]]) }), 'strict');
    expect(dated.weaponized).toBe(true);
    const undated = scoreOf(asOf(kevCve(), spec, { metasploitModified: new Map([[ID, after(3)]]) }), 'strict');
    expect(undated.weaponized).toBe(false);
    expect(undated.leftOut).toContain('metasploit');
    expect(undated.reasons.some((r) => r.id === 'x.none')).toBe(false);
    expect(scoreOf(asOf(kevCve(), spec, { metasploitModified: new Map([[ID, after(3)]]) }), 'upper').weaponized).toBe(true);
  });

  it('leaves Nuclei templates out of the strict scores (no dates) and in the undated variant', () => {
    const spec = { nuclei: { [ID]: [nucleiTemplate(ID)] } };
    expect(scoreOf(asOf(kevCve(), spec), 'strict').weaponized).toBe(false);
    expect(scoreOf(asOf(kevCve(), spec), 'upper').weaponized).toBe(true);
  });

  it('trusts an SSVC exploitation value only from an unchanged CISA container; the timestamp dates the rest', () => {
    const asse = ssvc('active', 'yes', 'total', before(2));
    // CISA's container unchanged since before the cutoff: the whole assessment counts, "active" included.
    const unchanged = scoreOf(asOf(kevCve({ ssvc: asse, adpUpdated: before(1) })), 'strict');
    expect(unchanged.exploited).toBe(true);
    expect(unchanged.reasons[0].id).toBe('ssvc.active');
    // Changed after the cutoff (as when CISA adds the KEV block): "active" may date from the listing.
    const changed = scoreOf(asOf(kevCve({ ssvc: asse, adpUpdated: after(1) })), 'strict');
    expect(changed.exploited).toBe(false);
    expect(changed.evidence.cve.ssvc).toMatchObject({ exploitation: '', automatable: 'yes', technical_impact: 'total' });
    expect(changed.leftOut).toEqual(['ssvc_exploitation']);
    expect(changed.reasons.some((r) => r.id === 'ssvc.total')).toBe(true);
    // Assessed on or after the listing day: left out entirely; the undated variant lowers "active".
    const late = kevCve({ ssvc: ssvc('active', 'yes', 'total', after(0)), adpUpdated: after(1) });
    const strict = scoreOf(asOf(late), 'strict');
    expect(strict.evidence.cve.ssvc).toBeNull();
    expect(strict.leftOut).toContain('ssvc');
    const upper = scoreOf(asOf(late), 'upper');
    expect(upper.exploited).toBe(false);
    expect(upper.evidence.cve.ssvc?.exploitation).toBe('none');
    expect(upper.leftOut).toEqual(['ssvc_active']);
    const withPoc = scoreOf(asOf(late, { exploitdb: { [ID]: [edb('7', '2026-10-01')] } }), 'upper');
    expect(withPoc.evidence.cve.ssvc?.exploitation).toBe('poc');
    // Stamped on the day before the listing, in a container changed since: CISA dates its listing
    // update that way, so the stamp cannot show the assessment predates the listing.
    for (const stamp of [before(1), '2026-10-19T00:00:00.000Z', before(1 / 24)]) {
      const dayBefore = scoreOf(asOf(kevCve({ ssvc: ssvc('active', 'yes', 'total', stamp), adpUpdated: after(0) })), 'strict');
      expect(dayBefore.evidence.cve.ssvc).toBeNull();
      expect(dayBefore.leftOut).toEqual(['ssvc']);
    }
    // The same stamp in a container unchanged since the cutoff: written before the listing, so it counts.
    expect(scoreOf(asOf(kevCve({ ssvc: ssvc('active', 'yes', 'total', before(1)), adpUpdated: before(1 / 24) })), 'strict').exploited).toBe(true);
    // A dated "none" needs nothing left out.
    expect(scoreOf(asOf(kevCve({ ssvc: ssvc('none', 'no', 'partial', before(3)), adpUpdated: after(1) })), 'strict').leftOut).toEqual([]);
  });

  it('leaves out CNA CVSS and vendor exploitation text when the CNA changed its record after the cutoff', () => {
    const changed = kevCve({ cnaUpdated: after(2), vendorInTheWild: true, cnaExploitMaturity: ['A'], ...cvss(9.8) });
    const strict = scoreOf(asOf(changed), 'strict');
    expect(strict.evidence.cve.cvss).toBeNull();
    expect(strict.exploited).toBe(false);
    expect(strict.leftOut).toContain('cna_record');
    const upper = scoreOf(asOf(changed), 'upper');
    expect(upper.exploited).toBe(true);
    expect(upper.evidence.cve.cvss?.score).toBe(9.8);
    // Unchanged since: time-matched, in both.
    expect(scoreOf(asOf(kevCve({ ...cvss(9.8) })), 'strict').evidence.cve.cvss?.score).toBe(9.8);
  });

  it('leaves out a CISA-ADP CVSS when CISA changed its container after the cutoff', () => {
    const adp = kevCve({ ...cvss(8.1, 'N', '3.1', 'cisa-adp'), adpUpdated: after(0) });
    expect(evidenceAsOf(asOf(adp), 'strict').cve.cvss).toBeNull();
    expect(evidenceAsOf(asOf(kevCve({ ...cvss(8.1, 'N', '3.1', 'cisa-adp'), adpUpdated: before(5) })), 'strict').cve.cvss?.score).toBe(8.1);
  });
});

describe('runBacktest', () => {
  const inputs = (o: Partial<BacktestInputs> = {}): BacktestInputs => ({
    epss: new Map([['2026-10-19', new Map([[ID, 0.3]])]]),
    reuse: new Map(),
    metasploitModified: new Map(),
    exploitdbAdded: new Map(),
    volumeFrom: '2026-05-07T03:17:00.000Z',
    ...o,
  });

  function run(cves: NormalizedCve[], kevs = [makeKev(ID, { dateAdded: LISTED })], spec: EnrichmentSpec = {}, o: Partial<BacktestInputs> = {}): BacktestReceipts {
    const enr = makeEnrichment({ ...spec, kev: kevs });
    const scored = cves.map((c) => scoreCve(c, enr, { now: NOW }));
    return runBacktest({ now: NOW, kev: enr.kev, cves: new Map(cves.map((c) => [c.id, c])), enr, inputs: inputs(o), scored, rows: new Map() });
  }

  it('judges each method on the same set and keeps misses, exclusions and old CVEs apart', () => {
    const old = 'CVE-2019-0001';
    const gone = 'CVE-2026-100009';
    const late = 'CVE-2026-100010';
    const b = run(
      [kevCve({ ...cvss(9.8) }), kevCve({ id: old, published: '2019-01-01T00:00:00.000Z', ...cvss(5.0) }), kevCve({ id: late, published: after(0) })],
      [makeKev(ID, { dateAdded: LISTED }), makeKev(old, { dateAdded: LISTED }), makeKev(gone, { dateAdded: LISTED }), makeKev(late, { dateAdded: LISTED }), makeKev('CVE-2020-0001', { dateAdded: '2026-01-01' })],
    );
    expect(b.hindsight).toBe(true);
    expect(b.listed).toBe(4); // the January listing is outside the 180 days
    expect(b.excluded).toEqual([
      { code: 'no_record', reason: 'No published CVE record', ids: [gone] },
      { code: 'not_public', reason: 'Published on or after the listing day, so no method could flag it before', ids: [late] },
    ]);
    const recent = b.sets.find((s) => s.key === 'recent')!;
    const olds = b.sets.find((s) => s.key === 'old')!;
    expect([recent.n, olds.n]).toEqual([1, 1]);
    const by = (s: typeof recent, m: string) => s.strict.find((x) => x.method === m)!;
    expect(by(recent, 'cvss7')).toEqual({ method: 'cvss7', n: 1, before: 1, earlier: 1, same_day: 0, lead: null });
    expect(by(recent, 'epss10').before).toBe(1); // 30% in the file of the day before
    expect(by(olds, 'cvss7').before).toBe(0); // CVSS 5.0: a miss, and it is counted
    expect(by(olds, 'epss10').before).toBe(0); // no EPSS score that day
    expect(b.items.find((i) => i.id === old)).toMatchObject({ old: true, epss: null, epss_date: '2026-10-19' });
  });

  it('flags EPSS from the file of the day before, and reuses carried values without a file', () => {
    const b = run([kevCve()], undefined, {}, { epss: new Map(), reuse: new Map([[`${ID}@${LISTED}`, { date: '2026-10-19', score: 0.25 }]]) });
    expect(b.items[0]).toMatchObject({ epss: 0.25, epss_date: '2026-10-19', strict: { epss10: true } });
    const missing = run([kevCve()], undefined, {}, { epss: new Map([['2026-10-19', null]]) });
    expect(missing.items[0]).toMatchObject({ epss: null, epss_date: null, strict: { epss10: false } });
    expect(missing.epss_missing).toEqual(['2026-10-19']);
    expect(missing.signals.find((s) => s.key === 'epss')?.affected).toBe(1);
  });

  it('adds undated evidence only in the upper variant, and reports alert volume over the period', () => {
    const b = run([kevCve({ cnaUpdated: after(1), ...cvss(9.8) }), makeCve({ id: 'CVE-2026-100050', published: '2026-10-30T00:00:00.000Z', ...cvss(9.8) })], undefined, {
      nuclei: { [ID]: [nucleiTemplate(ID)] },
    });
    const it0 = b.items[0];
    expect(it0.strict).toEqual({ cverdict: false, cvss7: false, epss10: true });
    expect(it0.upper).toEqual({ cverdict: true, cvss7: true, epss10: true });
    expect(it0.left_out).toEqual(['nuclei', 'cna_record']);
    expect(b.volume).toMatchObject({ n: 2, methods: [{ method: 'cverdict', flagged: 1 }, { method: 'cvss7', flagged: 2 }, { method: 'epss10', flagged: 0 }] });
  });
});

describe('carry-forward', () => {
  const no = { cverdict: false, cvss7: false, epss10: false };
  const zero = (n: number) => RECEIPT_METHODS.map((method) => ({ method, n, before: 0, earlier: 0, same_day: 0, lead: null }));
  const computed = (iso: string, o: Partial<BacktestReceipts> = {}): BacktestReceipts =>
    ({
      hindsight: true,
      computed_at: iso,
      score_model: SCORE_MODEL,
      listed: 4,
      items: [
        { id: ID, kev_added: LISTED, old: false, strict: no, upper: no, epss: 0.25, epss_date: '2026-10-19' },
        { id: 'CVE-2026-1', kev_added: LISTED, old: false, strict: no, upper: no, epss: null, epss_date: null },
      ],
      excluded: [{ code: 'not_public', reason: 'x', ids: ['CVE-2026-9'] }, { code: 'no_record', reason: 'y', ids: ['CVE-2026-8'] }],
      sets: [
        { key: 'recent', n: 2, strict: zero(2), upper: zero(2) },
        { key: 'old', n: 0, strict: zero(0), upper: zero(0) },
      ],
      signals: [],
      epss_missing: [],
      ...o,
    }) as unknown as BacktestReceipts;

  it(`carries a backtest younger than ${BACKTEST_REFRESH_DAYS} days, else plans a refresh reusing known EPSS values`, () => {
    const fresh = computed(new Date(NOW.getTime() - 2 * 86_400_000).toISOString());
    expect(decideBacktest(fresh, NOW)).toMatchObject({ carried: fresh, plan: null });
    expect(decideBacktest(fresh, NOW, true).plan).not.toBeNull();
    const stale = decideBacktest(computed(new Date(NOW.getTime() - 8 * 86_400_000).toISOString()), NOW);
    expect(stale.carried).toBeNull();
    expect([...stale.plan!.reuse]).toEqual([[`${ID}@${LISTED}`, { date: '2026-10-19', score: 0.25 }]]);
    expect(stale.plan!.volumeFrom.toISOString()).toBe('2026-05-07T03:17:00.000Z');
    // A CVE published after its listing stays excluded, so its EPSS is not downloaded again; one without a record may appear.
    expect([...stale.plan!.skip]).toEqual(['CVE-2026-9']);
    // From the future (a clock problem): refresh.
    expect(decideBacktest(computed('2026-12-01T00:00:00Z'), NOW).plan).not.toBeNull();
    expect(decideBacktest(null, NOW).note).toMatch(/no previous backtest/);
  });

  it('recomputes a recent copy from another score model, an inconsistent one, and one with missing EPSS days after a day', () => {
    const recent = new Date(NOW.getTime() - 2 * 86_400_000).toISOString();
    expect(backtestProblems(computed(recent))).toEqual([]);
    // Another model, or a copy from before score_model existed: never carried.
    expect(decideBacktest(computed(recent, { score_model: 'v0.0.1' }), NOW)).toMatchObject({ carried: null, note: expect.stringMatching(/score model v0\.0\.1/) });
    expect(decideBacktest(computed(recent, { score_model: undefined }), NOW).carried).toBeNull();
    // Figures that do not match the items (a stricter validate.ts would fail the run every hour for a week).
    const broken = computed(recent, { listed: 9 });
    expect(backtestProblems(broken)).toHaveLength(1);
    expect(decideBacktest(broken, NOW).carried).toBeNull();
    // EPSS files missing: retried a day later, not a week later; the values already known are reused.
    const missing = (iso: string) => computed(iso, { epss_missing: ['2026-10-19'] });
    expect(decideBacktest(missing(new Date(NOW.getTime() - 3_600_000).toISOString()), NOW).carried).not.toBeNull();
    const retry = decideBacktest(missing(recent), NOW);
    expect(retry.carried).toBeNull();
    expect(retry.plan!.reuse.size).toBe(1);
    expect(retry.note).toMatch(/1 EPSS days missing/);
  });

  it('recomputes a recent copy whose sets or items are not objects, instead of throwing', () => {
    const recent = new Date(NOW.getTime() - 2 * 86_400_000).toISOString();
    for (const o of [{ sets: [null] }, { items: [null] }, { sets: [{ key: 'recent', n: 2, strict: [null], upper: zero(2) }] }, { items: [{ id: ID, strict: null, upper: no }] }, { excluded: {} }] as const) {
      const bad = computed(recent, o as unknown as Partial<BacktestReceipts>);
      expect(() => backtestProblems(bad)).not.toThrow();
      expect(backtestProblems(bad).length).toBeGreaterThan(0);
      const d = decideBacktest(bad, NOW);
      expect(d.carried).toBeNull();
      expect(d.plan).not.toBeNull();
    }
  });

  it('retries a day later when a source had no data, and never publishes an empty backtest when KEV is down', () => {
    const recent = new Date(NOW.getTime() - 2 * 86_400_000).toISOString();
    const down = (iso: string) => computed(iso, { sources_down: ['Exploit-DB'] });
    expect(decideBacktest(down(new Date(NOW.getTime() - 3_600_000).toISOString()), NOW).carried).not.toBeNull();
    expect(decideBacktest(down(recent), NOW)).toMatchObject({ carried: null, note: expect.stringMatching(/Exploit-DB had no data/) });
    // Copies from before the field existed are carried as before.
    expect(decideBacktest(computed(recent), NOW).carried).not.toBeNull();

    const cve = makeCve({ id: ID, published: '2026-10-01T00:00:00Z', ...cvss(9.8) });
    const kev = [makeKev(ID, { dateAdded: LISTED })];
    const refresh: BacktestInputs = { epss: new Map(), reuse: new Map(), metasploitModified: new Map(), exploitdbAdded: new Map(), volumeFrom: '2026-05-07T03:17:00.000Z' };
    const build = (spec: EnrichmentSpec, previousBacktest: BacktestReceipts | null) =>
      buildOutput({ ingest: { ...makeIngest([cve], { ...spec, kev: spec.down?.includes('kev') ? [] : kev }), backtest: refresh }, now: NOW, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://x.test', previousBacktest });
    // A source down during a refresh is recorded, so the page can say so and the next day retries.
    expect(build({ down: ['exploitdb'] }, null).receipts.backtest?.sources_down).toEqual(['exploitdb']);
    expect(build({}, null).receipts.backtest).toMatchObject({ listed: 1, sources_down: [] });
    // KEV down: no listings to judge. Keep the previous backtest (if it adds up), else publish none.
    const old = computed('2026-10-01T00:00:00Z');
    const kept = build({ down: ['kev'] }, old);
    expect(kept.receipts.backtest).toBe(old);
    expect(kept.notes.join('\n')).toMatch(/not refreshed, kev has no data \(kept the one computed 2026-10-01/);
    expect(build({ down: ['kev'] }, null).receipts.backtest).toBeNull();
    expect(build({ down: ['kev'] }, computed('2026-10-01T00:00:00Z', { listed: 9 })).receipts.backtest).toBeNull();
  });

  it('reads the previous receipts.json defensively', () => {
    const dir = mkdtempSync(join(tmpdir(), 'backtest-'));
    try {
      expect(readPreviousBacktest(dir)).toBeNull();
      mkdirSync(join(dir, 'v1'));
      writeFileSync(join(dir, 'v1', 'receipts.json'), '{"backtest":{"hindsight":false}}');
      expect(readPreviousBacktest(dir)).toBeNull();
      writeFileSync(join(dir, 'v1', 'receipts.json'), 'not json');
      expect(readPreviousBacktest(dir)).toBeNull();
      writeFileSync(join(dir, 'v1', 'receipts.json'), JSON.stringify({ backtest: computed(NOW.toISOString()) }));
      expect(readPreviousBacktest(dir)?.computed_at).toBe(NOW.toISOString());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

it('kevAsOf keeps only listings from earlier days', () => {
  const cat = makeKevCatalog([makeKev('CVE-1', { dateAdded: '2026-10-19' }), makeKev('CVE-2', { dateAdded: LISTED }), makeKev('CVE-3', { dateAdded: '2026-10-21' })]);
  expect([...kevAsOf(cat, LISTED).entries.keys()]).toEqual(['CVE-1']);
});
