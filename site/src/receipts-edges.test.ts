import { describe, expect, it } from 'vitest';
import type { ForwardReceipts, MethodScore } from '../../shared/contract';
import { countOf, forwardHeadline, leadText, MIN_N_FOR_PCT } from './receipts';

const score = (method: MethodScore['method'], o: Partial<MethodScore> = {}): MethodScore => ({ method, n: 0, before: 0, earlier: 0, same_day: 0, lead: null, ...o });
const forward = (cv: Partial<MethodScore>, eligible: number): ForwardReceipts =>
  ({
    since: '2026-11-03T23:30:00.000Z',
    eligible,
    methods: [score('cverdict', { n: eligible, ...cv }), score('cvss7', { n: eligible }), score('epss10', { n: eligible })],
  }) as ForwardReceipts;

describe('receipts copy at the edges', () => {
  it('never says "a median of 0 days earlier": the same-day count says it', () => {
    const [, line] = forwardHeadline(forward({ before: 3, earlier: 1, same_day: 2, lead: { median: 0, q1: 0, q3: 0.5 } }, 4));
    expect(line).toBe('CVErdict flagged 3 of them first (2 of them on the listing day).');
    expect(line).not.toMatch(/0 days/);
    expect(forwardHeadline(forward({ before: 2, earlier: 2, lead: { median: 1, q1: 1, q3: 1 } }, 2))[1]).toBe('CVErdict flagged 2 of them first, a median of 1 day earlier.');
    expect(forwardHeadline(forward({ before: 2, earlier: 2, lead: { median: 0.5, q1: 0, q3: 1 } }, 2))[1]).toBe('CVErdict flagged 2 of them first, a median of 0.5 days earlier.');
  });

  it('dates the start in UTC, with the year, and uses one CVE in the singular', () => {
    expect(forwardHeadline(forward({}, 1))).toEqual(['Since Nov 3, 2026: CISA added 1 CVE we had already seen to KEV.', 'CVErdict flagged none of it first.']);
  });

  it('shows a share from exactly 10 CVEs on, never below, and never hides the count', () => {
    expect(countOf(0, MIN_N_FOR_PCT - 1)).toBe('0 of 9');
    expect(countOf(9, MIN_N_FOR_PCT - 1)).toBe('9 of 9');
    expect(countOf(0, MIN_N_FOR_PCT)).toBe('0 of 10 (0%)');
    expect(countOf(0, 0)).toBe('0 of 0');
  });

  it('shows quartiles only from 4 CVEs on', () => {
    expect(leadText({ median: 3, q1: 1, q3: 5 }, 3)).toBe('3 days');
    expect(leadText({ median: 3, q1: 1, q3: 5 }, 4)).toBe('3 days (1–5)');
  });
});
