/**
 * Pure helpers for The Surge's "last 30 days" chart and the monthly chart's tooltip: the day rows at
 * the viewer's evidence bar, KEV additions per day, the square-root axis, the takeaway line and the
 * change against the same month a year earlier.
 */
import type { KevEntry, Row, StatsFile } from '../../shared/contract';
import { dayOf } from './drill';
import { pubMs, tierAt } from './filters';
import { fmtDate, fmtInt, fmtMonth, fmtPct, plural } from './format';
import { shiftMonth, type MonthProgress } from './surge';

export type DayRow = StatsFile['daily'][number];

/**
 * Day rows at `knob`. stats.json counts `passed` at the default bar; the signal rows (every CVE that
 * can be Likely at a knob of 35 or more) move each day's count up or down. Exploited never depends
 * on the knob. Rows published outside the listed days are ignored.
 */
export function dailyAt(days: readonly DayRow[], signalRows: readonly Row[], knob: number): DayRow[] {
  const delta = new Map<string, number>();
  for (const r of signalRows) {
    const d = r.tier === 'likely' ? -1 : 0;
    const n = d + (tierAt(r, knob) === 'likely' ? 1 : 0);
    if (n === 0) continue;
    const k = dayOf(pubMs(r));
    delta.set(k, (delta.get(k) ?? 0) + n);
  }
  return days.map((d) => {
    const n = delta.get(d.date) ?? 0;
    if (n === 0) return d;
    return {
      ...d,
      passed: Math.min(d.published, Math.max(d.exploited, d.passed + n)),
    };
  });
}

/** CISA KEV additions per day (YYYY-MM-DD), from kev.json's recent entries. */
export function kevByDay(entries: readonly Pick<KevEntry, 'date_added'>[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const e of entries) {
    const k = typeof e.date_added === 'string' ? e.date_added.slice(0, 10) : '';
    if (/^\d{4}-\d{2}-\d{2}$/.test(k)) out.set(k, (out.get(k) ?? 0) + 1);
  }
  return out;
}

/** The axis top for a square-root scale: the max rounded up to 1, 2, 2.5 or 5 times a power of ten. */
export function sqrtTop(max: number): number {
  if (!(max > 0)) return 10;
  const p = Math.pow(10, Math.floor(Math.log10(max)));
  const f = max / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
}

/**
 * Tick values for a square-root axis from 0 to `top`, drawn `px` tall: round values (1, 2.5 and 5
 * times a power of ten, plus the top), keeping the highest first and dropping any that would sit
 * closer than `gap` px to one already kept. Ascending, always starting at 0.
 */
export function sqrtTicks(top: number, px: number, gap = 18): number[] {
  if (!(top > 0) || !(px > 0)) return [0];
  const cand = new Set<number>([top]);
  for (let p = 1; p <= top; p *= 10) for (const f of [1, 2.5, 5]) if (f * p < top) cand.add(f * p);
  const y = (v: number) => Math.sqrt(v / top) * px;
  const kept: number[] = [];
  for (const v of [...cand].sort((a, b) => b - a)) {
    if (kept.every((k) => Math.abs(y(k) - y(v)) >= gap) && y(v) >= gap) kept.push(v);
  }
  return [0, ...kept.reverse()];
}

/** True when the last day row is the UTC day `generatedAt` falls in, so it is still filling up. */
export function lastDayPartial(days: readonly DayRow[], generatedAt: string): boolean {
  const t = Date.parse(generatedAt);
  return days.length > 0 && !Number.isNaN(t) && dayOf(t) === days[days.length - 1].date;
}

export interface DailyTotals {
  published: number;
  passed: number;
  exploited: number;
  kev: number;
}

export function dailyTotals(days: readonly DayRow[], kev: ReadonlyMap<string, number>): DailyTotals {
  const t = { published: 0, passed: 0, exploited: 0, kev: 0 };
  for (const d of days) {
    t.published += d.published;
    t.passed += d.passed;
    t.exploited += d.exploited;
    t.kev += kev.get(d.date) ?? 0;
  }
  return t;
}

/**
 * One line under the chart: "Busiest day: Nov 10, with 2,062 CVEs. 78 cleared the bar. Over all 30
 * days, 2.7% did." The day still filling up never counts as the busiest. Empty when there is no data.
 */
export function dailyTakeaway(days: readonly DayRow[], partialLast: boolean, refYear?: number): string {
  const full = partialLast ? days.slice(0, -1) : days;
  const top = full.reduce<DayRow | null>((a, d) => (!a || d.published > a.published ? d : a), null);
  if (!top || top.published <= 0) return '';
  const all = days.reduce((a, d) => a + d.published, 0);
  const passed = days.reduce((a, d) => a + d.passed, 0);
  const cleared = top.passed === 0 ? 'none cleared the bar' : top.passed === 1 ? '1 cleared the bar' : `${fmtInt(top.passed)} cleared the bar`;
  return `Busiest day: ${fmtDate(top.date, refYear)}, with ${fmtInt(top.published)} CVEs, and ${cleared}. Over all ${days.length} days, ${fmtPct(passed / Math.max(1, all))} did.`;
}

export interface YearChange {
  /** The month a year earlier, YYYY-MM. */
  ref: string;
  /** now / then - 1. */
  change: number;
  /** True when the month is partial and compared with the same point (share of the month) a year earlier. */
  partial: boolean;
}

/**
 * Change against the same month one year earlier. A partial month is compared with that month's
 * count scaled to the same share of days. Null without a year-earlier row or when it is zero.
 */
export function yearChange(monthly: readonly { month: string }[], values: readonly number[], i: number, progress: MonthProgress): YearChange | null {
  const m = monthly[i];
  if (!m) return null;
  const ref = shiftMonth(m.month, -12);
  const j = monthly.findIndex((x) => x.month === ref);
  if (j < 0) return null;
  const partial = progress.partial && i === monthly.length - 1;
  const then = values[j] * (partial && progress.daysInMonth > 0 ? progress.elapsed / progress.daysInMonth : 1);
  if (!(then > 0)) return null;
  return { ref, change: values[i] / then - 1, partial };
}

/**
 * What the change is measured against: "Mar 2024", or "the same point in Nov 2025" for a partial
 * month. The partial comparison scales by the exact share of the month elapsed, not whole days, so
 * it does not say "the same days".
 */
export function yearRef(y: Pick<YearChange, 'ref' | 'partial'>): string {
  return `${y.partial ? 'the same point in ' : ''}${fmtMonth(y.ref)}`;
}

/**
 * The screen reader summary of the 30-day chart. It names the dates, because these are whole UTC
 * days and so do not add up to the rolling 30-day total shown elsewhere on the site.
 */
export function dailySummary(days: readonly DayRow[], t: DailyTotals, refYear?: number): string {
  if (days.length === 0) return 'No days to show.';
  const from = fmtDate(days[0].date, refYear);
  const to = fmtDate(days[days.length - 1].date, refYear);
  return `${plural(t.published, 'CVE')} published from ${from} to ${to}; ${fmtInt(t.passed)} cleared the evidence bar, ${fmtInt(t.exploited)} of them exploited.`;
}

/** "+38%", "−12%" or "about the same" (within half a percent). */
export function fmtChange(change: number): string {
  if (Math.abs(change) < 0.005) return 'about the same';
  return `${change > 0 ? '+' : '−'}${fmtPct(Math.abs(change))}`;
}
