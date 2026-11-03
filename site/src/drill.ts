/**
 * Pure logic for drilling from the waterfall into one UTC day: the `day` URL parameter, which
 * day a column opens, how many CVEs that day holds, and the column's time-range label.
 */
import { KNOB_DEFAULT } from '../../shared/contract';
import { DAY_MS, fmtDate, fmtHour, HOUR_MS } from './format';
import { href } from './router';

const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * A `day` parameter (YYYY-MM-DD) as the epoch ms of that UTC midnight, or null when it is not a
 * real calendar date ("2026-02-30", "2026-10-1", "yesterday" are all ignored).
 */
export function parseDay(raw: string | null | undefined): number | null {
  const m = raw ? DAY_RE.exec(raw.trim()) : null;
  if (!m) return null;
  const t = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return new Date(t).toISOString().slice(0, 10) === m[0] ? t : null;
}

/** The UTC day containing `ms`, as YYYY-MM-DD. */
export const dayOf = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

/** UTC midnight at or before `ms`. */
export const dayStart = (ms: number): number => Math.floor(ms / DAY_MS) * DAY_MS;

/** Whether `ms` falls on the UTC day that starts at `day`. */
export const onDay = (ms: number, day: number): boolean => ms >= day && ms < day + DAY_MS;

/** Whether any part of the UTC day that starts at `day` lies inside the window (its first and last days are partial). */
export const dayInWindow = (day: number, window: { readonly from: string; readonly to: string }): boolean => day + DAY_MS > Date.parse(window.from) && day <= Date.parse(window.to);

/** One waterfall column: `hours` hourly buckets from `from`, with per-tier counts. */
export interface Bin<C> {
  from: number;
  hours: number;
  c: C;
}

/** Hours per column so that every column is at least `pitch` px wide. */
export const hoursPerBin = (buckets: number, width: number, pitch: number): number => (width <= 0 ? 1 : Math.max(1, Math.ceil((buckets * pitch) / width)));

/** Group hourly tier counts into columns of `per` hours; the last column may be shorter. */
export function binsOf(counts: readonly (readonly number[])[], start: number, per: number): Bin<number[]>[] {
  const out: Bin<number[]>[] = [];
  for (let i = 0; i < counts.length; i += per) {
    const c = [0, 0, 0, 0];
    for (let j = i; j < Math.min(counts.length, i + per); j++) for (let k = 0; k < 4; k++) c[k] += counts[j][k];
    out.push({ from: start + i * HOUR_MS, hours: Math.min(per, counts.length - i), c });
  }
  return out;
}

/**
 * The day a column opens. A column can cross midnight (they span 2 to 9 hours at most widths),
 * so it opens the day it starts on, and the tooltip names that day.
 */
export const binDay = (from: number): string => dayOf(from);

/** Every CVE in the hourly buckets that fall on the UTC day `day` (ms), whatever its tier. */
export function dayTotal(counts: readonly (readonly number[])[], start: number, day: number): number {
  let n = 0;
  const first = Math.max(0, Math.ceil((day - start) / HOUR_MS));
  for (let i = first; i < counts.length && start + i * HOUR_MS < day + DAY_MS; i++) n += counts[i][0] + counts[i][1] + counts[i][2] + counts[i][3];
  return n;
}

/**
 * "Oct 13 · 14:00–16:00 UTC". A column that crosses midnight names both days
 * ("Oct 3 · 18:00 – Oct 4 · 01:00 UTC"); one that ends exactly at midnight stays on its day
 * ("Oct 3 · 22:00–24:00 UTC").
 */
export function binRange(from: number, hours: number, refYear?: number): string {
  const to = from + hours * HOUR_MS;
  const day = dayStart(from);
  const d1 = fmtDate(new Date(from).toISOString(), refYear);
  if (to <= day + DAY_MS) return `${d1} · ${fmtHour(from)}–${to === day + DAY_MS ? '24:00' : fmtHour(to)} UTC`;
  return `${d1} · ${fmtHour(from)} – ${fmtDate(new Date(to).toISOString(), refYear)} · ${fmtHour(to)} UTC`;
}

/** Explore filtered to one UTC day, highest score first, at the viewer's knob. */
export function exploreDayHref(day: string, knob: number = KNOB_DEFAULT): string {
  const q = new URLSearchParams({ day, sort: 'score' });
  if (knob !== KNOB_DEFAULT) q.set('knob', String(knob));
  return `${href('explore')}?${q.toString()}`;
}
