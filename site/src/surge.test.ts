import { describe, expect, it } from 'vitest';
import { LEDE_FALLBACK, busiestComplete, growth, ledeText, monthProgress, onPace, shiftMonth, windowLabel, type MonthRow } from './surge';

/** Consecutive months from `start`, one published count each. */
const months = (start: string, counts: number[]): MonthRow[] => counts.map((published, i) => ({ month: shiftMonth(start, i), published }));

describe('shiftMonth', () => {
  it('crosses year boundaries both ways', () => {
    expect(shiftMonth('2026-11', 2)).toBe('2027-01');
    expect(shiftMonth('2026-01', -1)).toBe('2025-12');
    expect(shiftMonth('2026-10', -12)).toBe('2025-10');
  });
});

describe('monthProgress', () => {
  it('reads the partial current month from generated_at in UTC', () => {
    const m = months('2026-10', [17050, 6998]);
    expect(monthProgress(m, '2026-11-12T21:47:32Z')).toEqual({ partial: true, daysElapsed: 12, daysInMonth: 30 });
  });
  it('uses UTC, not local time, at a day edge', () => {
    const m = months('2026-10', [1, 1]);
    expect(monthProgress(m, '2026-11-01T00:30:00Z').daysElapsed).toBe(1);
    expect(monthProgress(m, '2026-10-31T23:59:00-02:00').partial).toBe(true);
  });
  it('treats a last row from an earlier month as complete', () => {
    const m = months('2026-09', [1, 1]);
    expect(monthProgress(m, '2026-11-01T03:00:00Z')).toEqual({ partial: false, daysElapsed: 31, daysInMonth: 31 });
  });
  it('knows February in a leap year', () => {
    expect(monthProgress(months('2028-02', [1]), '2028-02-10T00:00:00Z').daysInMonth).toBe(29);
  });
});

describe('onPace', () => {
  it('projects the month and rounds to the nearest 100', () => {
    expect(onPace(6998, { partial: true, daysElapsed: 12, daysInMonth: 30 })).toBe(17500);
  });
  it('is hidden in the first 3 days of a month', () => {
    expect(onPace(900, { partial: true, daysElapsed: 3, daysInMonth: 30 })).toBeNull();
    expect(onPace(1200, { partial: true, daysElapsed: 4, daysInMonth: 30 })).toBe(9000);
  });
  it('is hidden when the month is complete', () => {
    expect(onPace(17050, { partial: false, daysElapsed: 31, daysInMonth: 31 })).toBeNull();
  });
});

describe('busiestComplete', () => {
  it('never picks the partial current month, even when it is the biggest', () => {
    const m = months('2026-09', [14929, 17050, 18000]);
    expect(busiestComplete(m, '2026-11-29T12:00:00Z')?.month).toBe('2026-10');
  });
  it('includes the last month once it is complete', () => {
    const m = months('2026-09', [14929, 17050, 18000]);
    expect(busiestComplete(m, '2026-12-01T01:00:00Z')?.month).toBe('2026-11');
  });
  it('returns null with no complete month', () => {
    expect(busiestComplete(months('2026-11', [5]), '2026-11-02T00:00:00Z')).toBeNull();
  });
});

describe('growth', () => {
  // Aug 2025 .. Nov 2026, real counts from the live data.
  const real = months('2025-08', [3629, 4319, 4274, 3019, 5493, 4302, 4616, 6236, 5813, 6933, 7949, 9759, 12257, 14929, 17050, 6998]);

  it('uses the last two complete months and ignores the partial current month', () => {
    const g = growth(real, '2026-11-12T21:47:32Z');
    expect(g).toMatchObject({ start: '2026-09', end: '2026-10' });
    expect(g!.ratio).toBeCloseTo((14929 + 17050) / (4319 + 4274), 6);
    expect(g!.ratio.toFixed(1)).toBe('3.7');
  });
  it('takes a window length, e.g. three months', () => {
    const g = growth(real, '2026-11-12T21:47:32Z', 3);
    expect(g).toMatchObject({ start: '2026-08', end: '2026-10' });
    expect(g!.ratio.toFixed(1)).toBe('3.6');
  });
  it('rolls forward once the current month is complete', () => {
    const withDec = [...real, { month: '2026-12', published: 100 }];
    expect(growth(withDec, '2026-12-03T00:00:00Z')).toMatchObject({ start: '2026-10', end: '2026-11' });
  });
  it('handles a window that spans a year boundary', () => {
    const m = months('2025-11', [10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 20, 30, 5]);
    const g = growth(m, '2027-01-05T00:00:00Z');
    expect(g).toMatchObject({ start: '2026-11', end: '2026-12' });
    expect(g!.ratio).toBe(2.5);
  });
  it('returns null when a needed month is missing', () => {
    const gap = real.filter((m) => m.month !== '2025-09');
    expect(growth(gap, '2026-11-12T00:00:00Z')).toBeNull();
    expect(growth(months('2026-01', [1, 2, 3]), '2026-04-01T00:00:00Z')).toBeNull();
  });
  it('returns null when the year-earlier window is zero', () => {
    const m = months('2025-09', [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, 6]);
    expect(growth(m, '2026-11-01T00:00:00Z')).toBeNull();
  });
  it('returns null for empty data', () => {
    expect(growth([], '2026-11-01T00:00:00Z')).toBeNull();
  });
});

describe('windowLabel', () => {
  it('names same-year and cross-year windows', () => {
    expect(windowLabel('2026-09', '2026-10')).toBe('September and October 2026');
    expect(windowLabel('2026-08', '2026-10')).toBe('August to October 2026');
    expect(windowLabel('2026-12', '2027-01')).toBe('December 2026 and January 2027');
    expect(windowLabel('2026-11', '2027-01')).toBe('November 2026 to January 2027');
    expect(windowLabel('2026-10', '2026-10')).toBe('October 2026');
  });
});

describe('ledeText', () => {
  it('writes the ratio to one decimal with the months from the data', () => {
    expect(ledeText({ start: '2026-09', end: '2026-10', ratio: 3.7215 })).toBe(
      'September and October 2026 saw 3.7 times the CVEs of a year earlier, while exploitation stayed rare. Most are long-tail: WordPress plugins and kernel bug fixes. Volume is not risk.',
    );
    expect(ledeText({ start: '2026-08', end: '2026-10', ratio: 3.62 })).toMatch(/^August to October 2026 saw 3\.6 times the CVEs of a year earlier,/);
    expect(ledeText({ start: '2026-12', end: '2027-01', ratio: 2 })).toMatch(/^December 2026 and January 2027 saw 2\.0 times the CVEs of a year earlier,/);
  });
  it('does not claim growth when there was none', () => {
    expect(ledeText({ start: '2026-09', end: '2026-10', ratio: 0.97 })).toMatch(/^September and October 2026 saw about as many CVEs as a year earlier,/);
  });
  it('stays short enough for two lines at desktop, even in the longest case', () => {
    expect(ledeText({ start: '2026-12', end: '2027-01', ratio: 113.7 }).length).toBeLessThanOrEqual(190);
    expect(LEDE_FALLBACK.length).toBeLessThanOrEqual(190);
  });
  it('falls back to a plain sentence without a number', () => {
    expect(ledeText(null)).toBe(LEDE_FALLBACK);
    expect(LEDE_FALLBACK).not.toMatch(/\d/);
  });
  it('never uses an em dash', () => {
    expect(ledeText({ start: '2026-09', end: '2026-10', ratio: 3 })).not.toContain('\u2014');
    expect(LEDE_FALLBACK).not.toContain('\u2014');
  });
});
