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
    const p = monthProgress(m, '2026-11-12T21:47:32Z');
    expect(p).toMatchObject({ partial: true, daysElapsed: 12, daysInMonth: 30 });
    expect(p.elapsed).toBeCloseTo(11 + (21 * 60 + 47.5) / 1440, 3);
  });
  it('uses UTC, not local time, at a day edge', () => {
    const m = months('2026-10', [1, 1]);
    expect(monthProgress(m, '2026-11-01T00:30:00Z').daysElapsed).toBe(1);
    expect(monthProgress(m, '2026-10-31T23:59:00-02:00').partial).toBe(true);
  });
  it('treats a last row from an earlier month as complete', () => {
    const m = months('2026-09', [1, 1]);
    expect(monthProgress(m, '2026-11-01T03:00:00Z')).toEqual({ partial: false, daysElapsed: 31, elapsed: 31, daysInMonth: 31 });
  });
  it('knows February in a leap year', () => {
    expect(monthProgress(months('2028-02', [1]), '2028-02-10T00:00:00Z').daysInMonth).toBe(29);
  });
});

describe('onPace', () => {
  it('projects the month and rounds to the nearest 100', () => {
    expect(onPace(6000, { partial: true, daysElapsed: 12, elapsed: 12, daysInMonth: 30 })).toBe(15000);
    expect(onPace(6998, monthProgress(months('2026-10', [17050, 6998]), '2026-11-12T21:47:32Z'))).toBe(17600);
  });
  it('divides by the time elapsed, not the day of the month, so it does not read low just after midnight', () => {
    // 00:10 UTC on the 4th: only about 3 days of data, so 50 CVEs is about 500 for the month, not 400.
    const p = monthProgress(months('2026-10', [1, 50]), '2026-11-04T00:10:00Z');
    expect(p.daysElapsed).toBe(4);
    expect(onPace(50, p)).toBe(500);
    // The same count late on the 3rd day and early on the 4th gives about the same estimate.
    expect(onPace(1500, monthProgress(months('2026-10', [1, 1500]), '2026-11-04T00:10:00Z'))).toBe(onPace(1500, { ...p, elapsed: 3 }));
  });
  it('is hidden in the first 3 days of a month', () => {
    expect(onPace(900, { partial: true, daysElapsed: 3, elapsed: 2.9, daysInMonth: 30 })).toBeNull();
    expect(onPace(1200, { partial: true, daysElapsed: 4, elapsed: 4, daysInMonth: 30 })).toBe(9000);
  });
  it('is hidden when the month is complete', () => {
    expect(onPace(17050, { partial: false, daysElapsed: 31, elapsed: 31, daysInMonth: 31 })).toBeNull();
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
      'September and October 2026 saw 3.7 times the CVEs of a year earlier. Exploitation stayed rare. Much of the growth is long-tail, like WordPress plugins and kernel fixes. Volume is not risk.',
    );
    expect(ledeText({ start: '2026-08', end: '2026-10', ratio: 3.62 })).toMatch(/^August to October 2026 saw 3\.6 times the CVEs of a year earlier\./);
    expect(ledeText({ start: '2026-12', end: '2027-01', ratio: 2 })).toMatch(/^December 2026 and January 2027 saw 2\.0 times the CVEs of a year earlier\./);
    expect(ledeText({ start: '2026-09', end: '2026-10', ratio: 1.1 })).toMatch(/saw 1\.1 times the CVEs/);
  });
  it('does not claim growth when there was none', () => {
    for (const ratio of [0.9, 0.97, 1.04]) {
      const t = ledeText({ start: '2026-09', end: '2026-10', ratio });
      expect(t).toBe('September and October 2026 saw about as many CVEs as a year earlier. Exploitation stayed rare. Volume is not risk.');
    }
  });
  it('says volume fell when it fell, and does not call it flat', () => {
    for (const ratio of [0.5, 0.84]) {
      const t = ledeText({ start: '2026-09', end: '2026-10', ratio });
      expect(t).toBe('September and October 2026 saw fewer CVEs than a year earlier. Exploitation stayed rare. Volume is not risk.');
      expect(t).not.toMatch(/about as many|growth/);
    }
  });
  it('does not say most CVEs are WordPress plugins and kernel fixes, only that much of the growth is', () => {
    for (const t of [ledeText({ start: '2026-09', end: '2026-10', ratio: 3.7 }), LEDE_FALLBACK]) {
      expect(t).toContain('Much of the growth is long-tail, like WordPress plugins and kernel fixes.');
      expect(t).not.toMatch(/\bMost\b/);
    }
  });
  it('stays short enough for two lines at desktop, even in the longest case', () => {
    // Measured at 1181 to 1440 px: 193 characters still wraps to two lines, 197 to three.
    expect(ledeText({ start: '2026-12', end: '2027-01', ratio: 13.7 }).length).toBeLessThanOrEqual(193);
    expect(LEDE_FALLBACK.length).toBeLessThanOrEqual(193);
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
