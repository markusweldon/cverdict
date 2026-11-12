/** Pure helpers for The Surge page: the partial current month, the on-pace estimate and the lede's growth window. */

export interface MonthRow {
  month: string; // YYYY-MM
  published: number;
}

const FULL_MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

/** Months in the lede's comparison window. Two complete months: recent enough to track the trend, and less noisy than one. */
export const LEDE_WINDOW = 2;

/** Days before the on-pace marker shows. Earlier than this, one busy day swings the estimate too far. */
export const PACE_MIN_DAYS = 4;

/** The on-pace marker may push the y axis up to this multiple of the busiest real value, no further. */
export const PACE_AXIS_HEADROOM = 1.2;

const ym = (y: number, m0: number): string => {
  const d = new Date(Date.UTC(y, m0, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
};

/** Shift a YYYY-MM key by a number of months. */
export function shiftMonth(month: string, by: number): string {
  return ym(Number(month.slice(0, 4)), Number(month.slice(5)) - 1 + by);
}

export interface MonthProgress {
  /** True when the last row is the month that generated_at falls in, so it is still filling up. */
  partial: boolean;
  /** Days of that month covered so far (UTC day of month of generated_at). */
  daysElapsed: number;
  daysInMonth: number;
}

/** How far through the last month the data is. A last row from an earlier month than generated_at is complete. */
export function monthProgress(monthly: readonly MonthRow[], generatedAt: string): MonthProgress {
  const last = monthly[monthly.length - 1];
  const at = new Date(generatedAt);
  if (!last || Number.isNaN(at.getTime())) return { partial: false, daysElapsed: 0, daysInMonth: 0 };
  const y = Number(last.month.slice(0, 4));
  const m0 = Number(last.month.slice(5)) - 1;
  const daysInMonth = new Date(Date.UTC(y, m0 + 1, 0)).getUTCDate();
  const partial = ym(at.getUTCFullYear(), at.getUTCMonth()) === last.month;
  return { partial, daysElapsed: partial ? at.getUTCDate() : daysInMonth, daysInMonth };
}

/** The rows that are complete months. */
export function completeMonths<T extends MonthRow>(monthly: readonly T[], generatedAt: string): readonly T[] {
  return monthProgress(monthly, generatedAt).partial ? monthly.slice(0, -1) : monthly;
}

/** Busiest complete month by published count, or null when there is none. */
export function busiestComplete<T extends MonthRow>(monthly: readonly T[], generatedAt: string): T | null {
  return completeMonths(monthly, generatedAt).reduce<T | null>((a, x) => (!a || x.published > a.published ? x : a), null);
}

/** Straight-line estimate for the partial month, rounded to the nearest 100. Null when the month is complete or too young. */
export function onPace(count: number, p: MonthProgress): number | null {
  if (!p.partial || p.daysElapsed < PACE_MIN_DAYS || p.daysInMonth <= 0) return null;
  return Math.round(((count / p.daysElapsed) * p.daysInMonth) / 100) * 100;
}

export interface Growth {
  /** First and last month of the recent window, YYYY-MM. */
  start: string;
  end: string;
  /** Published in the window / published in the same months one year earlier. */
  ratio: number;
}

/**
 * Year-on-year growth over the last `len` complete months. The partial current month is never used,
 * so the window rolls forward on its own when a month finishes. Null when a month is missing or the baseline is zero.
 */
export function growth(monthly: readonly MonthRow[], generatedAt: string, len = LEDE_WINDOW): Growth | null {
  const done = completeMonths(monthly, generatedAt);
  const last = done[done.length - 1];
  if (!last || len < 1) return null;
  const by = new Map(monthly.map((m) => [m.month, m.published]));
  let now = 0;
  let before = 0;
  for (let i = 0; i < len; i++) {
    const k = shiftMonth(last.month, -i);
    const a = by.get(k);
    const b = by.get(shiftMonth(k, -12));
    if (a === undefined || b === undefined) return null;
    now += a;
    before += b;
  }
  if (before <= 0) return null;
  return { start: shiftMonth(last.month, 1 - len), end: last.month, ratio: now / before };
}

const fullMonth = (k: string) => FULL_MONTHS[Number(k.slice(5)) - 1];

/** "September and October 2026", "August to October 2026", "December 2026 and January 2027", "October 2026". */
export function windowLabel(start: string, end: string): string {
  const sy = start.slice(0, 4);
  const ey = end.slice(0, 4);
  if (start === end) return `${fullMonth(end)} ${ey}`;
  const join = shiftMonth(start, 1) === end ? 'and' : 'to';
  return sy === ey ? `${fullMonth(start)} ${join} ${fullMonth(end)} ${ey}` : `${fullMonth(start)} ${sy} ${join} ${fullMonth(end)} ${ey}`;
}

const LEDE_TAIL = 'Most are long-tail: WordPress plugins and kernel bug fixes. Volume is not risk.';

/** Lede shown before stats load, or when there is no year-earlier window to compare with. Same length as the numeric one, so nothing jumps. */
export const LEDE_FALLBACK = 'CVE volume has grown fast while exploitation stayed rare. Most new CVEs are long-tail: WordPress plugins and kernel bug fixes. Volume is not risk.';

/** The page lede, with the growth figure when there is one. Kept under about 190 characters so it stays on two lines at desktop. */
export function ledeText(g: Growth | null): string {
  if (!g) return LEDE_FALLBACK;
  const when = windowLabel(g.start, g.end);
  const r = g.ratio.toFixed(1);
  if (Number(r) < 1.1) return `${when} saw about as many CVEs as a year earlier, and exploitation stayed rare. ${LEDE_TAIL}`;
  return `${when} saw ${r} times the CVEs of a year earlier, while exploitation stayed rare. ${LEDE_TAIL}`;
}
