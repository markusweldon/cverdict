/**
 * Receipts, part 1: the forward log. Real-time observations, no hindsight.
 *
 * Every run records, per CVE in the window, the time (to the minute) of the first run that saw it
 * and of the first run at which each method flagged it:
 *   cverdict  tier Exploited or Likely next at the default knob (KNOB_DEFAULT);
 *   cvss7     the CVSS base score the site shows (CNA, else CISA-ADP) is 7.0 or more;
 *   epss10    the EPSS score is 0.1 or more (only once EPSS has scored the CVE).
 * When a logged CVE appears in CISA KEV (at any age), the KEV dateAdded and the time of the run
 * that first saw the listing are recorded. Runs can come twice an hour, so times are kept to the
 * minute, and "before" compares those instants. KEV gives a date without a time, read as a US
 * Eastern day (CISA's time zone), so the day of a run time is taken in that zone to compare.
 *
 * A CVE is watched while it is in the window: a method that flags it only later is not counted, for
 * every method alike. Entries without a KEV listing are pruned after LOG_RETENTION_DAYS (their
 * counts move into `pruned`, so alert volume keeps them); entries with one are kept.
 *
 * The log lives in the `receipts` section of state.json (state.ts). Missing or unreadable state
 * starts a new log with a new `since`; nothing before it is ever inferred.
 */
import {
  KNOB_DEFAULT,
  RECEIPT_METHODS,
  tierFor,
  type AlertVolume,
  type ForwardReceipts,
  type LeadDays,
  type MethodScore,
  type ReceiptFlag,
  type ReceiptItem,
  type ReceiptMethod,
  type Row,
  type UncountedListing,
} from '../../shared/contract';
import type { StateSection } from './state';
import type { KevCatalog, ScoredCve } from './types';
import { DAY_MS, normalizeIso, normalizeYmd, ymd } from './util/dates';
import { asNumber, asObject } from './util/json';
import { normalizeCveId } from './util/text';

export const HOUR_MS = 3_600_000;
export const MINUTE_MS = 60_000;
/** Entries without a KEV listing are dropped this long after they were first seen. */
export const LOG_RETENTION_DAYS = 400;
/** A pause between runs longer than this is recorded as a gap. */
export const GAP_HOURS = 3;
const MAX_GAPS = 50;
export const CVSS_LINE = 7;
export const EPSS_LINE = 0.1;
/**
 * Counted listings carry the CVE's row for this long after the listing; older ones carry null (the
 * CVE page has it). The lists keep every listing since `since`, so rows on all of them would push
 * receipts.json past its budget within about two years.
 */
export const ROW_DAYS = 365;

/** One CVE in the log. Times are whole minutes since the Unix epoch (the run's minute, rounded down). */
export interface LogEntry {
  seen: number;
  flags: Record<ReceiptMethod, number | null>;
  kev: { added: string; seen: number } | null;
}

export interface ReceiptsLog {
  since: string;
  last: string;
  runs: number;
  gaps: [string, string][];
  /** Every gap since `since` (`gaps` keeps only the most recent MAX_GAPS). */
  gapTotal: { n: number; hours: number };
  entries: Map<string, LogEntry>;
  /** Totals of pruned entries, so alert volume still counts them. */
  pruned: { n: number } & Record<ReceiptMethod, number>;
}

const emptyPruned = (): ReceiptsLog['pruned'] => ({ n: 0, cverdict: 0, cvss7: 0, epss10: 0 });
export const minuteOf = (d: Date | string): number => Math.floor((typeof d === 'string' ? Date.parse(d) : d.getTime()) / MINUTE_MS);
export const minuteIso = (m: number): string => new Date(m * MINUTE_MS).toISOString();
/** KEV dateAdded has no time; it is read as a day in CISA's own (US Eastern) time zone. */
const ET_DAY = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit' });
/** The US Eastern day (YYYY-MM-DD) of a log time, to compare with a KEV dateAdded. */
export const etDay = (m: number): string => ET_DAY.format(new Date(m * MINUTE_MS));
/** A CVE ID as CVE List files spell it: no leading zero beyond the 4-digit minimum. */
const CANONICAL_ID_RE = /^CVE-\d{4}-(?:\d{4}|[1-9]\d{4,})$/;
/** Length of a gap in hours, to 0.1. */
const gapHours = (from: string, to: string): number => Math.round((Date.parse(to) - Date.parse(from)) / HOUR_MS * 10) / 10;

// ── Compact encoding ─────────────────────────────────────────────────────────────────────────
//
// The log can hold ~200,000 CVEs, so it is columnar: `ids` lists the CVE IDs sorted by year and
// sequence number, as `YYYY:first,delta,delta… YYYY:…`; `seen` holds minute offsets from `m0`;
// `cverdict`, `cvss7` and `epss10` hold minute offsets from that entry's `seen` ('' = never).
// Only canonical IDs are logged (CANONICAL_ID_RE), so every ID survives the numeric round trip. Each
// column is one comma-separated string, in `ids` order. KEV listings are a sparse object.

function idKey(id: string): [number, number] {
  const [, y, n] = id.split('-');
  return [Number(y), Number(n)];
}

function compareIds(a: string, b: string): number {
  const [ya, na] = idKey(a);
  const [yb, nb] = idKey(b);
  return ya - yb || na - nb;
}

export function encodeIds(ids: readonly string[]): string {
  const groups: string[] = [];
  let year = -1;
  let prev = 0;
  let parts: number[] = [];
  for (const id of ids) {
    const [y, n] = idKey(id);
    if (y !== year) {
      if (parts.length) groups.push(`${year}:${parts.join(',')}`);
      year = y;
      parts = [n];
    } else parts.push(n - prev);
    prev = n;
  }
  if (parts.length) groups.push(`${year}:${parts.join(',')}`);
  return groups.join(' ');
}

/** Null when the string is not a valid encoding. */
export function decodeIds(text: string): string[] | null {
  if (text === '') return [];
  const out: string[] = [];
  for (const group of text.split(' ')) {
    const m = /^(\d{4}):(\d+(?:,\d+)*)$/.exec(group);
    if (!m) return null;
    let n = 0;
    m[2].split(',').forEach((v, i) => {
      n = i === 0 ? Number(v) : n + Number(v);
      out.push(`CVE-${m[1]}-${String(n).padStart(4, '0')}`);
    });
  }
  // Must be strictly increasing (sorted, no duplicates); the zero-delta case is a duplicate.
  for (let i = 1; i < out.length; i++) if (compareIds(out[i - 1], out[i]) >= 0) return null;
  return out;
}

function decodeColumn(text: unknown, length: number, optional: boolean): (number | null)[] | null {
  if (typeof text !== 'string') return null;
  const parts = length === 0 && text === '' ? [] : text.split(',');
  if (parts.length !== length) return null;
  const out: (number | null)[] = [];
  for (const p of parts) {
    if (p === '' && optional) out.push(null);
    else if (/^\d{1,7}$/.test(p)) out.push(Number(p));
    else return null;
  }
  return out;
}

export interface EncodedLog {
  since: string;
  last: string;
  runs: number;
  gaps: [string, string][];
  /** [count, hours] of every gap since `since`. */
  gap_total: [number, number];
  pruned: ReceiptsLog['pruned'];
  /** Minute of `since`. */
  m0: number;
  ids: string;
  seen: string;
  cverdict: string;
  cvss7: string;
  epss10: string;
  kev: Record<string, [string, number]>;
}

export function encodeLog(log: ReceiptsLog): EncodedLog {
  const ids = [...log.entries.keys()].sort(compareIds);
  const m0 = minuteOf(log.since);
  const seen: number[] = [];
  const cols: Record<ReceiptMethod, string[]> = { cverdict: [], cvss7: [], epss10: [] };
  const kev: EncodedLog['kev'] = {};
  for (const id of ids) {
    const e = log.entries.get(id)!;
    seen.push(e.seen - m0);
    for (const m of RECEIPT_METHODS) cols[m].push(e.flags[m] === null ? '' : String(e.flags[m]! - e.seen));
    if (e.kev) kev[id] = [e.kev.added, e.kev.seen - m0];
  }
  return {
    since: log.since,
    last: log.last,
    runs: log.runs,
    gaps: log.gaps,
    gap_total: [log.gapTotal.n, log.gapTotal.hours],
    pruned: log.pruned,
    m0,
    ids: encodeIds(ids),
    seen: seen.join(','),
    cverdict: cols.cverdict.join(','),
    cvss7: cols.cvss7.join(','),
    epss10: cols.epss10.join(','),
    kev,
  };
}

/** The log in a state section, or null when any part is not understood (a new log starts). */
export function decodeLog(data: unknown): ReceiptsLog | null {
  const o = asObject(data);
  const since = normalizeIso(o?.since);
  const last = normalizeIso(o?.last);
  const runs = asNumber(o?.runs);
  const m0 = asNumber(o?.m0);
  if (!o || !since || !last || runs === null || !Number.isInteger(runs) || runs < 1 || m0 !== minuteOf(since) || last < since) return null;
  const ids = typeof o.ids === 'string' ? decodeIds(o.ids) : null;
  if (!ids) return null;
  const seen = decodeColumn(o.seen, ids.length, false);
  const cols = Object.fromEntries(RECEIPT_METHODS.map((m) => [m, decodeColumn(o[m], ids.length, true)])) as Record<ReceiptMethod, (number | null)[] | null>;
  if (!seen || RECEIPT_METHODS.some((m) => !cols[m])) return null;
  const kev = asObject(o.kev) ?? {};
  const entries = new Map<string, LogEntry>();
  ids.forEach((id, i) => {
    const s = m0 + seen[i]!;
    const flags = Object.fromEntries(RECEIPT_METHODS.map((m) => [m, cols[m]![i] === null ? null : s + cols[m]![i]!])) as LogEntry['flags'];
    entries.set(id, { seen: s, flags, kev: null });
  });
  for (const [key, value] of Object.entries(kev)) {
    const id = normalizeCveId(key);
    const e = id ? entries.get(id) : undefined;
    const added = Array.isArray(value) ? normalizeYmd(value[0]) : null;
    const at = Array.isArray(value) ? asNumber(value[1]) : null;
    if (!e || !added || at === null || !Number.isInteger(at) || at < 0) return null;
    e.kev = { added, seen: m0 + at };
  }
  const p = asObject(o.pruned);
  const pruned = emptyPruned();
  for (const k of ['n', ...RECEIPT_METHODS] as const) {
    const v = asNumber(p?.[k]);
    if (v === null || !Number.isInteger(v) || v < 0) return null;
    pruned[k] = v;
  }
  const gaps: [string, string][] = [];
  for (const g of Array.isArray(o.gaps) ? o.gaps : []) {
    const from = Array.isArray(g) ? normalizeIso(g[0]) : null;
    const to = Array.isArray(g) ? normalizeIso(g[1]) : null;
    if (from && to) gaps.push([from, to]);
  }
  // Logs written before gap_total existed hold every gap they saw (fewer than MAX_GAPS so far).
  const t = Array.isArray(o.gap_total) ? o.gap_total.map(asNumber) : null;
  const gapTotal = t ? { n: t[0], hours: t[1] } : { n: gaps.length, hours: gaps.reduce((a, [from, to]) => a + gapHours(from, to), 0) };
  if (gapTotal.n === null || !Number.isInteger(gapTotal.n) || gapTotal.n < gaps.length || gapTotal.hours === null || !(gapTotal.hours >= 0)) return null;
  return { since, last, runs, gaps, gapTotal: { n: gapTotal.n, hours: gapTotal.hours }, entries, pruned };
}

/** Version 2 keeps minutes; a version 1 log (hours, never published) starts fresh. */
export const RECEIPTS_SECTION: StateSection<ReceiptsLog> = { key: 'receipts', version: 2, parse: decodeLog };

// ── Update ─────────────────────────────────────────────────────────────────────────────────

const flagged = (s: ScoredCve): Record<ReceiptMethod, boolean> => {
  const tier = tierFor(s.score, s.exploited, s.weaponized, KNOB_DEFAULT);
  return {
    cverdict: tier === 'exploited' || tier === 'likely',
    cvss7: (s.cve.cvss?.score ?? -1) >= CVSS_LINE,
    epss10: (s.epss?.score ?? -1) >= EPSS_LINE,
  };
};

export interface LogUpdate {
  log: ReceiptsLog;
  /** False when the log was carried over unchanged (the run's clock is behind the log). */
  updated: boolean;
  notes: string[];
}

/**
 * Record this run. `scored` is every record this run scored and emits (window ∪ KEV ∪ woke): only
 * window records are watched, the rest can only bring a KEV listing. Pure; `previous` is not mutated.
 */
export function updateLog(previous: ReceiptsLog | null, scored: readonly ScoredCve[], kev: KevCatalog, now: Date): LogUpdate {
  const nowIso = now.toISOString();
  const notes: string[] = [];
  if (previous && Date.parse(previous.last) > now.getTime()) {
    notes.push(`the log's last run (${previous.last}) is later than this run; carried over unchanged`);
    return { log: previous, updated: false, notes };
  }
  const minute = minuteOf(now);
  const today = ymd(now);
  const log: ReceiptsLog = previous
    ? {
        ...previous,
        gaps: [...previous.gaps],
        pruned: { ...previous.pruned },
        entries: new Map([...previous.entries].map(([id, e]) => [id, { seen: e.seen, flags: { ...e.flags }, kev: e.kev && { ...e.kev } }])),
      }
    : { since: nowIso, last: nowIso, runs: 0, gaps: [], gapTotal: { n: 0, hours: 0 }, entries: new Map(), pruned: emptyPruned() };
  if (!previous) notes.push('no usable log in the previous state; a new log starts now');
  if (previous && now.getTime() - Date.parse(previous.last) > GAP_HOURS * HOUR_MS) {
    log.gaps.push([previous.last, nowIso]);
    log.gapTotal = { n: log.gapTotal.n + 1, hours: log.gapTotal.hours + gapHours(previous.last, nowIso) };
    notes.push(`gap since the last run (${previous.last})`);
  }
  log.gaps = log.gaps.slice(-MAX_GAPS);
  log.runs++;
  log.last = nowIso;

  let added = 0;
  let odd = 0;
  for (const s of scored) {
    if (!s.cve.inWindow || log.entries.has(s.cve.id)) continue;
    // A non-canonical ID (CVE-2026-01234) would come back as another ID after encoding, and the
    // duplicate would make the next run discard the whole log. Real records never use one.
    if (!CANONICAL_ID_RE.test(s.cve.id)) {
      odd++;
      continue;
    }
    log.entries.set(s.cve.id, { seen: minute, flags: { cverdict: null, cvss7: null, epss10: null }, kev: null });
    added++;
  }
  if (odd) notes.push(`${odd} non-canonical CVE IDs not logged`);

  // KEV listings for any logged CVE, at whatever age. The catalog first; the CISA-ADP KEV block
  // in the record covers a run without a catalog. Listings dated after `now` do not exist yet.
  let listings = 0;
  const record = (id: string, date: string | null) => {
    const e = log.entries.get(id);
    if (!e || e.kev || !date || date > today) return;
    e.kev = { added: date, seen: minute };
    listings++;
  };
  for (const k of kev.entries.values()) record(k.cveID, normalizeYmd(k.dateAdded));
  for (const s of scored) if (s.cve.adpKev) record(s.cve.id, s.cve.adpKev.dateAdded);

  // First flags. A listing this run can see but not record (no usable date, or dated after `now`)
  // would otherwise give a flag that seems to come before the listing: no method's flag is
  // recorded until the listing is, and then it comes with the listing ('after'). Every method
  // is held the same way.
  const newFlags: Record<ReceiptMethod, number> = { cverdict: 0, cvss7: 0, epss10: 0 };
  for (const s of scored) {
    if (!s.cve.inWindow) continue;
    const e = log.entries.get(s.cve.id);
    if (!e) continue;
    const unrecorded = !e.kev && (kev.entries.has(s.cve.id) || s.cve.adpKev !== null);
    const f = flagged(s);
    for (const m of RECEIPT_METHODS) {
      if (e.flags[m] === null && f[m] && !unrecorded) {
        e.flags[m] = minute;
        newFlags[m]++;
      }
    }
  }

  const cutoff = minute - LOG_RETENTION_DAYS * 24 * 60;
  let pruned = 0;
  for (const [id, e] of log.entries) {
    if (e.kev || e.seen >= cutoff) continue;
    log.pruned.n++;
    for (const m of RECEIPT_METHODS) if (e.flags[m] !== null) log.pruned[m]++;
    log.entries.delete(id);
    pruned++;
  }
  notes.push(
    `${added} new CVEs, ${log.entries.size} in the log; first flags this run: ${RECEIPT_METHODS.map((m) => `${m} ${newFlags[m]}`).join(', ')}; ` +
      `${listings} KEV listings recorded${pruned ? `; ${pruned} entries pruned` : ''}`,
  );
  return { log, updated: true, notes };
}

// ── Metrics ────────────────────────────────────────────────────────────────────────────────

/** Linear interpolation between closest ranks (R type 7, Excel QUARTILE.INC), rounded to 0.1. */
export function quantile(sorted: readonly number[], q: number): number {
  if (sorted.length === 0) throw new Error('quantile of an empty list');
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  const v = sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
  return Math.round(v * 10) / 10;
}

export function leadDays(leads: readonly number[]): LeadDays | null {
  if (leads.length === 0) return null;
  const sorted = [...leads].sort((a, b) => a - b);
  return { median: quantile(sorted, 0.5), q1: quantile(sorted, 0.25), q3: quantile(sorted, 0.75) };
}

/** Whole UTC days from `fromDay` to `toDay` (YYYY-MM-DD). */
export function dayDiff(fromDay: string, toDay: string): number {
  return Math.round((Date.parse(`${toDay}T00:00:00Z`) - Date.parse(`${fromDay}T00:00:00Z`)) / DAY_MS);
}

/**
 * One method on one KEV listing. Flagged before the listing means: by a run earlier than the one
 * that first saw the listing, and on or before the KEV dateAdded (a US Eastern day). Same
 * definition for every method.
 */
export function outcomeOf(flagAt: number | null, kev: { added: string; seen: number }): ReceiptFlag {
  if (flagAt === null) return { at: null, outcome: 'never', lead: null };
  const at = minuteIso(flagAt);
  const lead = dayDiff(etDay(flagAt), kev.added);
  if (flagAt < kev.seen && lead >= 0) return { at, outcome: lead >= 1 ? 'earlier' : 'same_day', lead };
  return { at, outcome: 'after', lead: null };
}

/** Score methods over items that each carry a ReceiptFlag per method. */
export function scoreMethods(items: readonly { flags: Record<ReceiptMethod, ReceiptFlag> }[]): MethodScore[] {
  return RECEIPT_METHODS.map((method) => {
    const flags = items.map((i) => i.flags[method]);
    const earlier = flags.filter((f) => f.outcome === 'earlier').length;
    const sameDay = flags.filter((f) => f.outcome === 'same_day').length;
    const leads = flags.filter((f) => f.lead !== null).map((f) => f.lead!);
    return { method, n: items.length, before: earlier + sameDay, earlier, same_day: sameDay, lead: leadDays(leads) };
  });
}

/** A KEV listing the log can judge: the CVE was seen by an earlier run, on or before the listing date (US Eastern). */
export function isEligible(e: LogEntry): e is LogEntry & { kev: NonNullable<LogEntry['kev']> } {
  return e.kev !== null && e.seen < e.kev.seen && etDay(e.seen) <= e.kev.added;
}

export function forwardReceipts(log: ReceiptsLog, kev: KevCatalog, rows: ReadonlyMap<string, Row>, now: Date, watchDays: number): ForwardReceipts {
  // KEV dates are Eastern days: a log that started at 00:17 UTC started on the Eastern day before.
  const sinceDay = etDay(minuteOf(log.since));
  const today = ymd(now);
  const inRange = (d: string) => d >= sinceDay && d <= today;
  const rowFrom = ymd(new Date(now.getTime() - ROW_DAYS * DAY_MS));
  const items: ReceiptItem[] = [];
  const uncounted: UncountedListing[] = [];
  const counted = new Set<string>();
  for (const [id, e] of log.entries) {
    if (!e.kev || !inRange(e.kev.added)) continue;
    counted.add(id);
    if (!isEligible(e)) {
      uncounted.push({ id, kev_added: e.kev.added, reason: 'listed_first' });
      continue;
    }
    const k = e.kev;
    items.push({
      id,
      kev_added: k.added,
      first_seen: minuteIso(e.seen),
      flags: Object.fromEntries(RECEIPT_METHODS.map((m) => [m, outcomeOf(e.flags[m], k)])) as ReceiptItem['flags'],
      row: k.added >= rowFrom ? (rows.get(id) ?? null) : null,
    });
  }
  for (const k of kev.entries.values()) {
    const added = normalizeYmd(k.dateAdded);
    if (!added || !inRange(added) || counted.has(k.cveID) || log.entries.has(k.cveID)) continue;
    // KEV records are always scored, so a listing without a row has no published record.
    uncounted.push({ id: k.cveID, kev_added: added, reason: rows.has(k.cveID) ? 'older' : 'no_record' });
  }
  const newest = (a: { kev_added: string; id: string }, b: { kev_added: string; id: string }) => b.kev_added.localeCompare(a.kev_added) || a.id.localeCompare(b.id);
  items.sort(newest);
  uncounted.sort(newest);

  const watched = log.entries.size + log.pruned.n;
  const volume: AlertVolume[] = RECEIPT_METHODS.map((method) => {
    let n = log.pruned[method];
    for (const e of log.entries.values()) if (e.flags[method] !== null) n++;
    return { method, n: watched, flagged: n };
  });
  return {
    since: log.since,
    last: log.last,
    runs: log.runs,
    gaps: log.gaps.map(([from, to]) => ({ from, to })),
    gap_total: { n: log.gapTotal.n, hours: Math.round(log.gapTotal.hours * 10) / 10 },
    watch_days: watchDays,
    listed: items.length + uncounted.length,
    eligible: items.length,
    methods: scoreMethods(items),
    volume,
    items,
    uncounted,
  };
}

/** For tests and tools: the CVE IDs of a log in its stored order. */
export function sortedIds(ids: Iterable<string>): string[] {
  return [...ids].sort(compareIds);
}
