/** UTC date helpers. Every date in the pipeline is UTC; nothing depends on the host time zone. */

export const DAY_MS = 86_400_000;

// Date, optional time (T or space), optional fraction, optional offset (Z, ±hh:mm, ±hhmm, ±hh).
const ISO_RE = /^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(\.\d+)?)?)?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?$/;

/**
 * Parse an ISO 8601 date or date-time. A missing offset means UTC (`Date.parse` would use local
 * time). Returns null for anything else, including impossible dates such as 2026-02-30.
 */
export function parseIsoDate(value: unknown): Date | null {
  if (typeof value !== 'string') return null;
  const m = ISO_RE.exec(value.trim());
  if (!m) return null;
  const [, y, mo, d, hh = '00', mi = '00', ss = '00', frac = '', tz = 'Z'] = m;
  const offset = tz === 'Z' || tz === 'z' ? 'Z' : `${tz.slice(0, 3)}:${tz.length > 3 ? tz.slice(-2) : '00'}`;
  const ms = Date.parse(`${y}-${mo}-${d}T${hh}:${mi}:${ss}${frac.slice(0, 4)}${offset}`);
  if (Number.isNaN(ms)) return null;
  // Date.parse rolls 2026-02-30 over to March; reject it by checking the calendar date survived.
  const check = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d)));
  if (check.getUTCMonth() !== Number(mo) - 1 || check.getUTCDate() !== Number(d)) return null;
  return new Date(ms);
}

/** Canonical ISO string (`2026-10-13T19:01:34.060Z`) for a parseable date, else null. */
export function normalizeIso(value: unknown): string | null {
  return parseIsoDate(value)?.toISOString() ?? null;
}

/** `YYYY-MM-DD` (UTC). */
export function ymd(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** `YYYY-MM` (UTC) — the key of History month counters. */
export function monthKey(date: Date): string {
  return date.toISOString().slice(0, 7);
}

/** A `YYYY-MM-DD` string if `value` is a valid calendar date (time part ignored), else null. */
export function normalizeYmd(value: unknown): string | null {
  const d = parseIsoDate(value);
  return d ? ymd(d) : null;
}

export function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * DAY_MS);
}

/** Fractional days from `from` to `to` (negative when `to` is earlier). */
export function daysBetween(from: Date, to: Date): number {
  return (to.getTime() - from.getTime()) / DAY_MS;
}
