/**
 * The homepage counter: whole days since CISA last added a CVE to KEV, which CVEs reset it, and
 * the longest stretch without a listing in kev.json's window (its entries cover the last 30
 * days). KEV dates are calendar days; days are counted in UTC.
 */
import type { KevEntry } from '../../shared/contract';

const DAY_MS = 86_400_000;
const dayStart = (ms: number) => Math.floor(ms / DAY_MS) * DAY_MS;

export interface KevStreak {
  /** Whole days since the newest listing: 0 when CISA listed something today. */
  days: number;
  /** The newest listing day, YYYY-MM-DD. */
  last: string;
  /** The CVEs listed that day, highest score first, unscored last. */
  resetBy: KevEntry[];
  /** The longest run of days with no listing between the window's listing days, and since the last one. */
  longestGap: number;
}

export function kevStreak(entries: readonly KevEntry[], now: number): KevStreak | null {
  const days = [...new Set(entries.map((e) => e.date_added).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)))].sort();
  if (!days.length) return null;
  const last = days[days.length - 1];
  const today = dayStart(now);
  const at = (d: string) => Date.parse(`${d}T00:00:00Z`);
  const since = Math.max(0, Math.round((today - at(last)) / DAY_MS));
  let longest = since;
  for (let i = 1; i < days.length; i++) longest = Math.max(longest, Math.round((at(days[i]) - at(days[i - 1])) / DAY_MS) - 1);
  const resetBy = entries.filter((e) => e.date_added === last).sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || a.id.localeCompare(b.id));
  return { days: since, last, resetBy, longestGap: longest };
}
