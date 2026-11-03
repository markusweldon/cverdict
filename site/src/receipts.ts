/** Pure helpers for the Receipts page: labels, small-sample rules and the headline sentence. */
import type { BacktestItem, ForwardReceipts, LeadDays, MethodScore, ReceiptFlag, ReceiptMethod } from '../../shared/contract';
import { fmtDate, fmtInt, fmtPct, plural } from './format';

/** Below this many CVEs a share is not shown: the count is, with a note that the sample is small. */
export const MIN_N_FOR_PCT = 10;

export const METHOD_LABEL: Readonly<Record<ReceiptMethod, string>> = {
  cverdict: 'CVErdict',
  cvss7: 'CVSS 7 or more',
  epss10: 'EPSS 10% or more',
};

export const METHOD_NOTE: Readonly<Record<ReceiptMethod, string>> = {
  cverdict: 'Exploited or Likely next at the default knob',
  cvss7: 'Patch everything rated 7.0 or higher',
  epss10: 'Patch everything with an EPSS score of 10% or more',
};

/** "12 of 40 (30%)", or "3 of 7" while the sample is too small for a share. */
export function countOf(part: number, n: number): string {
  const base = `${fmtInt(part)} of ${fmtInt(n)}`;
  return n >= MIN_N_FOR_PCT ? `${base} (${fmtPct(part / n)})` : base;
}

/** Days with at most one decimal: 3 → "3", 2.5 → "2.5". */
const days = (d: number) => (Number.isInteger(d) ? fmtInt(d) : d.toFixed(1));

/** "7 days (3–12)", "1 day", or "—" when nothing was flagged before the listing. */
export function leadText(lead: LeadDays | null, before: number): string {
  if (!lead) return '—';
  const median = `${days(lead.median)} ${lead.median === 1 ? 'day' : 'days'}`;
  return before >= 4 ? `${median} (${days(lead.q1)}–${days(lead.q3)})` : median;
}

export function methodScore(scores: readonly MethodScore[], method: ReceiptMethod): MethodScore | undefined {
  return scores.find((s) => s.method === method);
}

/**
 * The forward headline: "Since Nov 3, 2026: CISA added 14 CVEs we had already seen to KEV.
 * CVErdict flagged 9 of them before CISA listed them, a median of 6 days earlier."
 */
export function forwardHeadline(f: ForwardReceipts): string[] {
  // Always with the year: the log's start is a fixed date, not "this week".
  const since = fmtDate(f.since, Number.NaN);
  const cv = methodScore(f.methods, 'cverdict');
  if (f.eligible === 0) return [`Since ${since}, CISA has not added any CVE we had already seen to KEV. The first ones will show up here.`];
  const first = `Since ${since}: CISA added ${plural(f.eligible, 'CVE')} we had already seen to KEV.`;
  if (!cv || cv.before === 0) return [first, `CVErdict flagged none of ${f.eligible === 1 ? 'it' : 'them'} before CISA listed ${f.eligible === 1 ? 'it' : 'them'}.`];
  const sameDay = cv.same_day > 0 ? ` (${fmtInt(cv.same_day)} of them on the listing day)` : '';
  // A median of 0 days is a same-day majority: the same-day count below says it in plain words.
  const median = cv.lead && cv.lead.median > 0 ? `, a median of ${days(cv.lead.median)} ${cv.lead.median === 1 ? 'day' : 'days'} earlier` : '';
  const them = f.eligible === 1 ? 'it' : 'them';
  return [first, `CVErdict flagged ${fmtInt(cv.before)} of ${them} before CISA listed ${cv.before === 1 ? 'it' : 'them'}${median}${sameDay}.`];
}

/** One method's verdict on one forward CVE, in words. */
export function flagText(f: ReceiptFlag): string {
  switch (f.outcome) {
    case 'earlier':
      return `${f.lead} ${f.lead === 1 ? 'day' : 'days'} earlier`;
    case 'same_day':
      return 'same day, before the listing';
    case 'after':
      return 'only at or after the listing';
    default:
      return 'not flagged';
  }
}

export const isBefore = (f: ReceiptFlag): boolean => f.outcome === 'earlier' || f.outcome === 'same_day';

export type BacktestFilter = 'all' | 'hit' | 'miss';

export function isBacktestFilter(v: string | null): v is BacktestFilter {
  return v === 'all' || v === 'hit' || v === 'miss';
}

/** Backtest items by CVErdict's strict verdict. */
export function filterBacktest(items: readonly BacktestItem[], filter: BacktestFilter): BacktestItem[] {
  if (filter === 'all') return [...items];
  return items.filter((i) => i.strict.cverdict === (filter === 'hit'));
}

/** "yes", "only with undated evidence" (`upper`) or "no" for one method on one backtest CVE. */
export function backtestMark(i: BacktestItem, m: ReceiptMethod): 'yes' | 'upper' | 'no' {
  return i.strict[m] ? 'yes' : i.upper[m] ? 'upper' : 'no';
}
