import { describe, expect, it } from 'vitest';
import type { KevEntry } from '../../shared/contract';
import { kevStreak } from './kevstreak';
import { sameDaysLastYear } from './surge';

const e = (id: string, date_added: string, score: number | null = null) => ({ id, date_added, vendor: 'V', product: 'P', score }) as unknown as KevEntry;

describe('kevStreak', () => {
  it('counts whole UTC days since the newest listing, and names what reset it, highest score first', () => {
    const entries = [e('CVE-A', '2026-11-20', 40), e('CVE-B', '2026-11-24', 30), e('CVE-C', '2026-11-24', 90), e('CVE-D', '2026-11-24')];
    const s = kevStreak(entries, Date.parse('2026-11-27T23:30:00Z'))!;
    expect(s.days).toBe(3);
    expect(s.last).toBe('2026-11-24');
    expect(s.resetBy.map((x) => x.id)).toEqual(['CVE-C', 'CVE-B', 'CVE-D']);
    // 20th to 24th: three days without a listing; since the 24th: three days.
    expect(s.longestGap).toBe(3);
  });

  it('reads 0 on a day with a listing, and nothing without entries', () => {
    expect(kevStreak([e('CVE-A', '2026-11-27')], Date.parse('2026-11-27T01:00:00Z'))?.days).toBe(0);
    expect(kevStreak([], Date.now())).toBeNull();
  });
});

describe('sameDaysLastYear', () => {
  it('counts this year and the same days of last year, the current month in proportion', () => {
    const monthly = [
      ...Array.from({ length: 12 }, (_, i) => ({ month: `2025-${String(i + 1).padStart(2, '0')}`, published: 100, kev_added: 10 })),
      { month: '2026-01', published: 300, kev_added: 12 },
      { month: '2026-02', published: 150, kev_added: 6 },
    ];
    // 14 of February's 28 days: January 2025 in full and half of February 2025.
    expect(sameDaysLastYear(monthly, '2026-02-14T12:00:00Z', (m) => m.published)).toEqual({ year: 2026, now: 450, before: 150 });
    expect(sameDaysLastYear(monthly, '2026-02-14T12:00:00Z', (m) => m.kev_added)).toEqual({ year: 2026, now: 18, before: 15 });
    expect(sameDaysLastYear(monthly.slice(12), '2026-02-14T12:00:00Z', (m) => m.published)).toBeNull();
  });
});
