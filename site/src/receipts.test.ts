import { describe, expect, it } from 'vitest';
import { KNOB_DEFAULT, type BacktestItem, type BacktestReceipts, type ForwardReceipts, type MethodScore } from '../../shared/contract';
import { backtestAt, backtestMark, countOf, filterBacktest, flagText, forwardHeadline, leadText } from './receipts';

const score = (method: MethodScore['method'], o: Partial<MethodScore> = {}): MethodScore => ({ method, n: 0, before: 0, earlier: 0, same_day: 0, lead: null, ...o });

function forward(o: Partial<ForwardReceipts> = {}): ForwardReceipts {
  return {
    since: '2026-11-03T03:00:00.000Z',
    last: '2026-12-01T03:00:00.000Z',
    runs: 600,
    gaps: [],
    gap_total: { n: 0, hours: 0 },
    watch_days: 30,
    listed: 0,
    eligible: 0,
    methods: [score('cverdict'), score('cvss7'), score('epss10')],
    volume: [],
    items: [],
    uncounted: [],
    ...o,
  };
}

describe('receipts helpers', () => {
  it('shows counts always and a share only from 10 CVEs on', () => {
    expect(countOf(3, 7)).toBe('3 of 7');
    expect(countOf(4, 10)).toBe('4 of 10 (40%)');
    expect(countOf(317, 16726)).toBe('317 of 16,726 (1.9%)');
  });

  it('writes the headline from the forward figures, with the year of the start', () => {
    expect(forwardHeadline(forward())).toEqual(['Since Nov 3, 2026, CISA has not added any CVE we had already seen to KEV. The first ones will show up here.']);
    const f = forward({ eligible: 14, methods: [score('cverdict', { n: 14, before: 9, earlier: 8, same_day: 1, lead: { median: 6, q1: 2, q3: 11 } }), score('cvss7'), score('epss10')] });
    expect(forwardHeadline(f)).toEqual([
      'Since Nov 3, 2026: CISA added 14 CVEs we had already seen to KEV.',
      'CVErdict flagged 9 of them before CISA listed them, a median of 6 days earlier (1 of them on the listing day).',
    ]);
    expect(forwardHeadline(forward({ eligible: 1, methods: [score('cverdict', { n: 1 })] }))[1]).toBe('CVErdict flagged none of it before CISA listed it.');
  });

  it('describes lead times and outcomes in plain words', () => {
    expect(leadText(null, 0)).toBe('—');
    expect(leadText({ median: 1, q1: 1, q3: 1 }, 1)).toBe('1 day');
    expect(leadText({ median: 6.5, q1: 2, q3: 11.3 }, 8)).toBe('6.5 days (2–11.3)');
    expect(flagText({ at: null, outcome: 'never', lead: null })).toBe('not flagged');
    expect(flagText({ at: 'x', outcome: 'earlier', lead: 1 })).toBe('1 day earlier');
    expect(flagText({ at: 'x', outcome: 'same_day', lead: 0 })).toBe('same day, before the listing');
    expect(flagText({ at: 'x', outcome: 'after', lead: null })).toBe('only at or after the listing');
  });

  it('marks and filters backtest CVEs by the strict result, with the undated variant apart', () => {
    const item = (id: string, strict: boolean, upper: boolean): BacktestItem =>
      ({ id, strict: { cverdict: strict, cvss7: false, epss10: false }, upper: { cverdict: upper, cvss7: true, epss10: false } }) as BacktestItem;
    const items = [item('a', true, true), item('b', false, true), item('c', false, false)];
    expect(filterBacktest(items, 'hit').map((i) => i.id)).toEqual(['a']);
    expect(filterBacktest(items, 'miss').map((i) => i.id)).toEqual(['b', 'c']);
    expect(filterBacktest(items, 'all')).toHaveLength(3);
    expect([backtestMark(items[0], 'cverdict'), backtestMark(items[1], 'cverdict'), backtestMark(items[2], 'cverdict'), backtestMark(items[2], 'cvss7')]).toEqual(['yes', 'upper', 'no', 'upper']);
  });
});

describe('backtestAt (the track-record line on Today)', () => {
  const item = (score: number, chips: string[] = [], old = false): BacktestItem =>
    ({ id: `CVE-2026-${score}`, old, score, chips, strict: { cverdict: false, cvss7: false, epss10: false }, upper: { cverdict: false, cvss7: false, epss10: false } }) as unknown as BacktestItem;
  const bt = (items: BacktestItem[]): BacktestReceipts => ({ items }) as unknown as BacktestReceipts;
  const items = [item(30), item(42), item(50), item(56), item(64), item(20, ['kev.listed']), item(10, ['ssvc.active']), item(15, ['x.metasploit']), item(12, ['x.nuclei']), item(18, ['x.exploitdb']), item(90, [], true)];

  it('counts recent items only, with exploitation and Metasploit or Nuclei passing at any bar', () => {
    expect(backtestAt(bt(items), 50)).toEqual({ flagged: 7, n: 10 });
    expect(backtestAt(bt(items), 40)).toEqual({ flagged: 8, n: 10 });
    expect(backtestAt(bt(items), 65)).toEqual({ flagged: 4, n: 10 });
  });

  it('never flags more at a higher bar', () => {
    let last = Infinity;
    for (let k = 30; k <= 80; k++) {
      const f = backtestAt(bt(items), k)!.flagged;
      expect(f).toBeLessThanOrEqual(last);
      last = f;
    }
  });

  it('agrees with the stored strict verdict when that verdict came from the same rule', () => {
    const stored = items.map((i) => ({ ...i, strict: { ...i.strict, cverdict: i.chips.some((c) => ['kev.listed', 'ssvc.active', 'x.metasploit', 'x.nuclei'].includes(c)) || i.score >= KNOB_DEFAULT } }));
    expect(backtestAt(bt(stored), KNOB_DEFAULT)!.flagged).toBe(stored.filter((i) => !i.old && i.strict.cverdict).length);
  });

  it('is null (the line hides) without a backtest or without recent CVEs', () => {
    expect(backtestAt(null, 50)).toBeNull();
    expect(backtestAt(undefined, 50)).toBeNull();
    expect(backtestAt(bt([]), 50)).toBeNull();
    expect(backtestAt(bt([item(90, [], true)]), 50)).toBeNull();
    expect(backtestAt({} as BacktestReceipts, 50)).toBeNull();
  });
});
