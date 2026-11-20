import { describe, expect, it } from 'vitest';
import { KNOB_DEFAULT, tierFor, type Row } from '../../shared/contract';
import { dailyAt, dailyTakeaway, dailyTotals, fmtChange, kevByDay, lastDayPartial, sqrtTicks, sqrtTop, yearChange, type DayRow } from './daily';
import { monthProgress, shiftMonth } from './surge';

function row(id: number, pub: string, s: number, opts: Partial<Row> = {}): Row {
  const x = opts.x ?? 0;
  const w = opts.w ?? 0;
  return {
    id: `CVE-2026-${10_000 + id}`,
    pub,
    cna: 'Acme',
    v: 'Acme',
    p: 'Widget',
    t: 'bug',
    s,
    tier: tierFor(s, x === 1, w === 1, KNOB_DEFAULT),
    x,
    w,
    k: 0,
    ai: 0,
    c: [],
    r: [],
    cv: null,
    e: null,
    kd: null,
    b: null,
    ...opts,
  };
}

const days: DayRow[] = [
  { date: '2026-11-18', published: 700, passed: 20, exploited: 1 },
  { date: '2026-11-19', published: 1021, passed: 9, exploited: 1 },
  { date: '2026-11-20', published: 7, passed: 0, exploited: 0 },
];

describe('dailyAt', () => {
  it('is the stats.json rows at the default knob', () => {
    const rows = [row(1, '2026-11-18T10:00:00Z', KNOB_DEFAULT + 5), row(2, '2026-11-19T23:59:00Z', KNOB_DEFAULT - 5)];
    expect(dailyAt(days, rows, KNOB_DEFAULT)).toEqual(days);
  });

  it('moves Likely rows in and out by their UTC publication day', () => {
    const rows = [row(1, '2026-11-18T10:00:00Z', 52), row(2, '2026-11-19T23:59:00Z', 44), row(3, '2026-11-19T00:00:00Z', 47)];
    const strict = dailyAt(days, rows, 55);
    expect(strict.map((d) => d.passed)).toEqual([days[0].passed - (rows[0].tier === 'likely' ? 1 : 0), days[1].passed, 0]);
    const broad = dailyAt(days, rows, 40);
    const gained = (r: Row) => (r.tier !== 'likely' ? 1 : 0);
    expect(broad[1].passed).toBe(days[1].passed + gained(rows[1]) + gained(rows[2]));
    expect(broad[1].published).toBe(days[1].published);
  });

  it('never counts exploited or weaponized rows as moving, and stays within exploited..published', () => {
    const rows = [row(1, '2026-11-19T01:00:00Z', 20, { x: 1 }), row(2, '2026-11-19T02:00:00Z', 20, { w: 1 })];
    expect(dailyAt(days, rows, 65)).toEqual(days);
    const tiny: DayRow[] = [{ date: '2026-11-19', published: 2, passed: 1, exploited: 1 }];
    const many = Array.from({ length: 5 }, (_, i) => row(10 + i, '2026-11-19T05:00:00Z', 45));
    expect(dailyAt(tiny, many, 40)[0].passed).toBe(2);
    const fall = Array.from({ length: 5 }, (_, i) => row(20 + i, '2026-11-19T05:00:00Z', 54));
    expect(dailyAt(tiny, fall, 60)[0].passed).toBe(1);
  });

  it('ignores rows outside the listed days', () => {
    expect(dailyAt(days, [row(1, '2026-10-01T00:00:00Z', 45)], 40)).toEqual(days);
  });
});

describe('kevByDay', () => {
  it('counts additions per day and skips bad dates', () => {
    const m = kevByDay([{ date_added: '2026-11-18' }, { date_added: '2026-11-18' }, { date_added: '2026-11-19T00:00:00Z' }, { date_added: 'soon' }, { date_added: null as unknown as string }]);
    expect([...m]).toEqual([
      ['2026-11-18', 2],
      ['2026-11-19', 1],
    ]);
  });
});

describe('sqrtTop and sqrtTicks', () => {
  it('rounds the top up to 1, 2, 2.5 or 5 times a power of ten', () => {
    expect(sqrtTop(2062)).toBe(2500);
    expect(sqrtTop(1270)).toBe(2000);
    expect(sqrtTop(78)).toBe(100);
    expect(sqrtTop(0)).toBe(10);
  });

  it('keeps round ticks at least the gap apart, top first', () => {
    const t = sqrtTicks(2500, 210);
    expect(t[0]).toBe(0);
    expect(t[t.length - 1]).toBe(2500);
    expect(t).toEqual([...t].sort((a, b) => a - b));
    const px = t.map((v) => Math.sqrt(v / 2500) * 210);
    for (let i = 2; i < px.length; i++) expect(px[i] - px[i - 1]).toBeGreaterThanOrEqual(18);
    expect(px[1]).toBeGreaterThanOrEqual(18);
  });

  it('degrades to a bare zero', () => {
    expect(sqrtTicks(0, 200)).toEqual([0]);
    expect(sqrtTicks(100, 0)).toEqual([0]);
  });
});

describe('lastDayPartial', () => {
  it('is true when generated_at falls on the last day (UTC)', () => {
    expect(lastDayPartial(days, '2026-11-20T00:47:36Z')).toBe(true);
    expect(lastDayPartial(days, '2026-11-21T00:01:00Z')).toBe(false);
    expect(lastDayPartial([], '2026-11-20T00:47:36Z')).toBe(false);
    expect(lastDayPartial(days, 'nope')).toBe(false);
  });
});

describe('dailyTotals', () => {
  it('adds up the window and the KEV additions on its days', () => {
    expect(
      dailyTotals(
        days,
        new Map([
          ['2026-11-19', 2],
          ['2026-10-01', 5],
        ]),
      ),
    ).toEqual({ published: 1728, passed: 29, exploited: 2, kev: 2 });
  });
});

describe('dailyTakeaway', () => {
  it('names the busiest full day and the window share', () => {
    expect(dailyTakeaway(days, true, 2026)).toBe('Busiest day: Nov 19, with 1,021 CVEs, and 9 cleared the bar. Over all 3 days, 1.7% did.');
  });

  it('never picks the day still filling up, and handles none and one', () => {
    const d: DayRow[] = [
      { date: '2026-11-19', published: 10, passed: 1, exploited: 0 },
      { date: '2026-11-20', published: 50, passed: 0, exploited: 0 },
    ];
    expect(dailyTakeaway(d, true, 2026)).toContain('Nov 19, with 10 CVEs, and 1 cleared the bar');
    expect(dailyTakeaway(d, false, 2026)).toContain('Nov 20, with 50 CVEs, and none cleared the bar');
    expect(dailyTakeaway([], false)).toBe('');
  });
});

describe('yearChange', () => {
  const months = (start: string, counts: number[]) => counts.map((published, i) => ({ month: shiftMonth(start, i), published }));

  it('compares a complete month with the same month a year earlier', () => {
    const m = months('2025-10', [100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 150, 60]);
    const p = monthProgress(m, '2026-11-15T12:00:00Z');
    const v = m.map((x) => x.published);
    expect(yearChange(m, v, 12, p)).toEqual({
      ref: '2025-10',
      change: 0.5,
      partial: false,
    });
  });

  it('scales the year-earlier month to the same share of days for the partial month', () => {
    const m = months('2025-11', [300, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 150]);
    const p = monthProgress(m, '2026-11-16T00:00:00Z');
    const r = yearChange(
      m,
      m.map((x) => x.published),
      12,
      p,
    )!;
    expect(r.partial).toBe(true);
    expect(r.ref).toBe('2025-11');
    expect(r.change).toBeCloseTo(0, 6);
  });

  it('is null without a year-earlier month or when it is zero', () => {
    const m = months('2026-01', [10, 20]);
    const p = monthProgress(m, '2026-05-01T00:00:00Z');
    expect(yearChange(m, [10, 20], 1, p)).toBeNull();
    const z = months('2025-01', [0, ...Array(11).fill(1), 5]);
    expect(
      yearChange(
        z,
        z.map((x) => x.published),
        12,
        monthProgress(z, '2026-05-01T00:00:00Z'),
      ),
    ).toBeNull();
  });
});

describe('fmtChange', () => {
  it('signs the change and calls tiny ones the same', () => {
    expect(fmtChange(0.38)).toBe('+38%');
    expect(fmtChange(-0.12)).toBe('−12%');
    expect(fmtChange(0.001)).toBe('about the same');
  });
});
