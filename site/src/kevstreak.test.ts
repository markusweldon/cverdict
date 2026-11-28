import { describe, expect, it } from 'vitest';
import type { KevEntry } from '../../shared/contract';
import { kevStreak } from './kevstreak';

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

