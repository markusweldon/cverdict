import { describe, expect, it } from 'vitest';
import type { KevLagYear } from '../../shared/contract';
import { chartYears, fmtDays, lagTakeaway, withinWeek } from './kevlag';

const row = (year: number, buckets: number[], median: number | null, partial = false): KevLagYear => ({
  year,
  count: buckets.reduce((a, v) => a + v, 0),
  buckets,
  median_days: median,
  partial,
});

describe('chartYears', () => {
  it('drops the 2021 and 2022 backlog years and empty years', () => {
    const rows = [row(2021, [0, 0, 0, 0, 1, 9], 900), row(2022, [0, 0, 0, 0, 0, 3], 1400), row(2023, [0, 1, 1, 0, 0, 0], 3), row(2024, [0, 0, 0, 0, 0, 0], null)];
    expect(chartYears(rows).map((r) => r.year)).toEqual([2023]);
    expect(chartYears(undefined)).toEqual([]);
  });
});

describe('withinWeek and fmtDays', () => {
  it('counts the same day and the week, not those listed before publication', () => {
    expect(withinWeek(row(2026, [5, 2, 3, 1, 0, 0], 4))).toBe(5);
  });
  it('writes days', () => {
    expect([fmtDays(1), fmtDays(11), fmtDays(21.5), fmtDays(1436), fmtDays(null)]).toEqual(['1 day', '11 days', '21.5 days', '1,436 days', '—']);
  });
});

describe('lagTakeaway', () => {
  it('says when the share barely moved instead of calling it faster', () => {
    const t = lagTakeaway([row(2025, [0, 40, 60, 50, 0, 100], 26), row(2026, [0, 45, 55, 50, 0, 100], 11, true)]);
    expect(t).toBe('2026 so far: CISA listed 250 CVEs, 40% of them within a week of publication, with a median of 11 days. That is about the same share as in 2025 (40%).');
  });
  it('names a real move up or down', () => {
    expect(lagTakeaway([row(2024, [0, 10, 10, 0, 0, 80], 400), row(2025, [0, 30, 30, 0, 0, 40], 20)])).toMatch(/That is up from 20% in 2024\.$/);
    expect(lagTakeaway([row(2024, [0, 30, 30, 0, 0, 40], 20), row(2025, [0, 10, 10, 0, 0, 80], 400)])).toMatch(/That is down from 60% in 2024\.$/);
  });
  it('has one sentence for a single year and nothing for none', () => {
    expect(lagTakeaway([row(2023, [0, 1, 0, 0, 0, 1], 3)])).toBe('2023: CISA listed 2 CVEs, 50% of them within a week of publication, with a median of 3 days.');
    expect(lagTakeaway([])).toBeNull();
  });
});
