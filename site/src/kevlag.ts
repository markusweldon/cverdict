/** Time to KEV on The Surge: which stats.json kev_lag years to chart, and the sentence under the chart. */
import { KEV_LAG_BUCKETS, KEV_LAG_FIRST_YEAR, type KevLagBucket, type KevLagYear } from '../../shared/contract';
import { fmtInt, fmtPct } from './format';

export const KEV_LAG_LABELS: Record<KevLagBucket, string> = {
  before: 'Before the CVE was published',
  day: 'Same day',
  week: 'Within a week',
  month: 'Within a month',
  year: 'Within a year',
  later: 'Over a year later',
};

/** Short labels for the legend and the table head. */
export const KEV_LAG_SHORT: Record<KevLagBucket, string> = {
  before: 'Before',
  day: 'Same day',
  week: '≤ 7 days',
  month: '≤ 30 days',
  year: '≤ 1 year',
  later: '> 1 year',
};

/** The years to chart: from KEV_LAG_FIRST_YEAR, and only those with additions. */
export function chartYears(rows: readonly KevLagYear[] | undefined): KevLagYear[] {
  return (rows ?? []).filter((r) => r.year >= KEV_LAG_FIRST_YEAR && r.count > 0);
}

/** Additions listed on the day the CVE was published or within 7 days after (the "day" and "week" buckets). */
export function withinWeek(r: KevLagYear): number {
  return r.buckets[KEV_LAG_BUCKETS.indexOf('day')] + r.buckets[KEV_LAG_BUCKETS.indexOf('week')];
}

/** "11 days", "1 day", "2.5 days", "—". */
export function fmtDays(days: number | null): string {
  if (days === null || !Number.isFinite(days)) return '—';
  const n = Math.abs(days) >= 100 ? fmtInt(Math.round(days)) : String(days);
  return `${n} ${days === 1 ? 'day' : 'days'}`;
}

/**
 * The sentence under the chart, about the latest charted year next to the one before. It says what the data says,
 * including when nothing moved: a share within 3 points of last year is "about the same", not "faster".
 */
export function lagTakeaway(years: readonly KevLagYear[]): string | null {
  const last = years[years.length - 1];
  if (!last) return null;
  const share = withinWeek(last) / last.count;
  const lead = `${last.partial ? `${last.year} so far` : last.year}: CISA listed ${fmtInt(last.count)} CVEs, ${fmtPct(share)} of them within a week of publication, with a median of ${fmtDays(last.median_days)}.`;
  const prev = years[years.length - 2];
  if (!prev) return lead;
  const before = withinWeek(prev) / prev.count;
  const diff = share - before;
  const trend = Math.abs(diff) < 0.03 ? `about the same share as in ${prev.year} (${fmtPct(before)})` : `${diff > 0 ? 'up' : 'down'} from ${fmtPct(before)} in ${prev.year}`;
  return `${lead} That is ${trend}.`;
}
