/**
 * Pure state and series for The Surge's monthly chart: the controls as URL query parameters, the date
 * range, grouping by month, quarter or year, the severity, CNA and KEV filters (from v1/surge.json),
 * the year-earlier comparison, and the CSV of what is on screen.
 */
import { SEVERITY_BANDS, type SeverityBand, type StatsFile, type SurgeFile } from '../../shared/contract';
import { cnaName } from '../../shared/cna';
import { fmtMonth } from './format';
import { monthProgress, shiftMonth, type MonthProgress } from './surge';

type Month = StatsFile['monthly'][number];

export type Group = 'month' | 'quarter' | 'year';
export type Preset = 'all' | '12m' | '24m' | '5y';
export type Overlay = 'kevadd' | 'kevpub' | 'ai';
export type Count = 'published' | 'reserved';

export const GROUPS: readonly Group[] = ['month', 'quarter', 'year'];
export const PRESETS: readonly { id: Preset; label: string; months: number | null }[] = [
  { id: '12m', label: '12 months', months: 12 },
  { id: '24m', label: '24 months', months: 24 },
  { id: '5y', label: '5 years', months: 60 },
  { id: 'all', label: 'All', months: null },
];
export const OVERLAYS: readonly Overlay[] = ['kevpub', 'kevadd', 'ai'];
export const BAND_LABELS: Readonly<Record<SeverityBand, string>> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None or no score' };

/** The CNAs behind the "Exclude WordPress" and "Exclude Linux kernel" quick toggles (as on Today). */
export const WORDPRESS_CNAS: readonly string[] = ['wordfence', 'wpscan', 'patchstack'];
export const KERNEL_CNAS: readonly string[] = ['linux'];

export interface View {
  /** Used when `from` and `to` are both null. */
  preset: Preset;
  /** A custom range (YYYY-MM, inclusive); either end may be open. */
  from: string | null;
  to: string | null;
  group: Group;
  count: Count;
  /** Severity bands to count; empty counts every band. */
  sev: SeverityBand[];
  /** Stack the bands instead of drawing one line. */
  stack: boolean;
  /** Only this CNA (lower case), or null. */
  cnaOnly: string | null;
  /** Leave these CNAs out (lower case). Ignored while cnaOnly is set. */
  cnaOut: string[];
  /** Only CVEs in the CISA KEV catalog. */
  kev: boolean;
  log: boolean;
  compare: boolean;
  lines: Overlay[];
}

export const DEFAULT_LINES: readonly Overlay[] = ['kevadd', 'ai'];

export const DEFAULT_VIEW: View = {
  preset: 'all',
  from: null,
  to: null,
  group: 'month',
  count: 'published',
  sev: [],
  stack: false,
  cnaOnly: null,
  cnaOut: [],
  kev: false,
  log: false,
  compare: false,
  lines: [...DEFAULT_LINES],
};

/** Every query parameter the chart owns, so a reset can clear them all. */
export const VIEW_KEYS = ['range', 'from', 'to', 'group', 'count', 'sev', 'view', 'cna', 'kev', 'scale', 'compare', 'lines'] as const;

const MONTH_RE = /^(\d{4})-(0[1-9]|1[0-2])$/;
const CNA_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;

const monthOrNull = (v: string | null): string | null => (v && MONTH_RE.test(v) && v >= '1999-01' ? v : null);

/** The view a URL asks for. Anything unknown or malformed falls back to the default. */
export function readView(q: URLSearchParams): View {
  const v: View = { ...DEFAULT_VIEW, sev: [], cnaOut: [], lines: [...DEFAULT_LINES] };
  const range = q.get('range');
  if (PRESETS.some((p) => p.id === range)) v.preset = range as Preset;
  v.from = monthOrNull(q.get('from'));
  v.to = monthOrNull(q.get('to'));
  if (v.from && v.to && v.from > v.to) [v.from, v.to] = [v.to, v.from];
  const group = q.get('group');
  if (group === 'quarter' || group === 'year') v.group = group;
  if (q.get('count') === 'reserved') v.count = 'reserved';
  const sev = (q.get('sev') ?? '').toLowerCase().split(',');
  v.sev = SEVERITY_BANDS.filter((b) => sev.includes(b));
  if (v.sev.length === SEVERITY_BANDS.length) v.sev = [];
  v.stack = q.get('view') === 'severity';
  for (const raw of (q.get('cna') ?? '').toLowerCase().split(',')) {
    const part = raw.trim();
    const out = part.startsWith('-');
    const name = out ? part.slice(1) : part;
    if (!CNA_RE.test(name)) continue;
    if (out) {
      if (!v.cnaOut.includes(name)) v.cnaOut.push(name);
    } else v.cnaOnly ??= name;
  }
  if (v.cnaOnly) v.cnaOut = [];
  v.kev = q.get('kev') === '1';
  v.log = q.get('scale') === 'log';
  v.compare = q.get('compare') === '1';
  const lines = q.get('lines');
  if (lines !== null) v.lines = lines === 'none' ? [] : OVERLAYS.filter((o) => lines.split(',').includes(o));
  return v;
}

/** Query parameters for a view: null for every default, so the default view has a clean URL. */
export function viewQuery(v: View): Record<(typeof VIEW_KEYS)[number], string | null> {
  const custom = v.from !== null || v.to !== null;
  const sameLines = v.lines.length === DEFAULT_LINES.length && DEFAULT_LINES.every((o) => v.lines.includes(o));
  const cna = v.cnaOnly ? v.cnaOnly : v.cnaOut.length ? v.cnaOut.map((c) => `-${c}`).join(',') : null;
  return {
    range: !custom && v.preset !== 'all' ? v.preset : null,
    from: v.from,
    to: v.to,
    group: v.group === 'month' ? null : v.group,
    count: v.count === 'published' ? null : v.count,
    sev: v.sev.length && v.sev.length < SEVERITY_BANDS.length ? SEVERITY_BANDS.filter((b) => v.sev.includes(b)).join(',') : null,
    view: v.stack ? 'severity' : null,
    cna,
    kev: v.kev ? '1' : null,
    scale: v.log ? 'log' : null,
    compare: v.compare ? '1' : null,
    lines: sameLines ? null : v.lines.length ? OVERLAYS.filter((o) => v.lines.includes(o)).join(',') : 'none',
  };
}

/** "?from=…" for a view ('' for the default), keys in a fixed order. */
export function viewSearch(v: View): string {
  const q = new URLSearchParams();
  for (const [k, val] of Object.entries(viewQuery(v))) if (val !== null) q.set(k, val);
  const s = q.toString().replace(/%2C/gi, ',');
  return s ? `?${s}` : '';
}

// ── data the filters can use ──

/** surge.json, when it covers every month of stats.json (an older or mismatched file would skew the counts). */
export function usableSurge(monthly: readonly Month[], surge: SurgeFile | null | undefined): SurgeFile | null {
  if (!surge || !monthly.length || !Array.isArray(surge.severity) || surge.start !== monthly[0].month) return null;
  return surge.severity.length >= monthly.length ? surge : null;
}

export interface FilterIndex {
  cnas: { cna: string; key: string; label: string; total: number }[];
  /** CNA index by lower-case key. */
  byKey: ReadonlyMap<string, number>;
  /** KEV cells by month index. */
  kev: ReadonlyMap<number, readonly [number, number, number, number][]>;
}

export function filterIndex(surge: SurgeFile): FilterIndex {
  const cnas = surge.cnas.map((c) => ({ cna: c.cna, key: c.cna.toLowerCase(), label: cnaName(c.cna), total: c.severity.reduce((a, r) => a + r.reduce((x, y) => x + y, 0), 0) }));
  const kev = new Map<number, [number, number, number, number][]>();
  for (const cell of surge.kev) {
    const list = kev.get(cell[0]) ?? [];
    list.push(cell);
    kev.set(cell[0], list);
  }
  return { cnas, byKey: new Map(cnas.map((c, i) => [c.key, i])), kev };
}

/** True when the view narrows the count with a filter that needs surge.json. */
export const filtered = (v: View): boolean => v.sev.length > 0 || v.cnaOnly !== null || v.cnaOut.length > 0 || v.kev;

/** The filters that apply: the CNA names that surge.json lists (others are ignored). */
export function activeCnas(v: View, idx: FilterIndex | null): { only: number | null; out: number[] } {
  if (!idx) return { only: null, out: [] };
  const only = v.cnaOnly !== null ? (idx.byKey.get(v.cnaOnly) ?? null) : null;
  const out = v.cnaOnly !== null ? [] : v.cnaOut.map((k) => idx.byKey.get(k)).filter((i): i is number => i !== undefined);
  return { only, out };
}

const ZERO = (): number[] => SEVERITY_BANDS.map(() => 0);

function cnaRow(surge: SurgeFile, c: number, i: number): readonly number[] | null {
  const e = surge.cnas[c];
  return e ? (e.severity[i - e.from] ?? null) : null;
}

/** Band counts for month index i under the CNA and KEV selection (severity is applied later). */
export function monthBands(surge: SurgeFile, idx: FilterIndex, i: number, sel: { only: number | null; out: readonly number[] }, kevOnly: boolean): number[] {
  if (kevOnly) {
    const out = ZERO();
    for (const [, c, b, n] of idx.kev.get(i) ?? []) {
      if (sel.only !== null ? c === sel.only : !sel.out.includes(c)) out[b] += n;
    }
    return out;
  }
  if (sel.only !== null) return [...(cnaRow(surge, sel.only, i) ?? ZERO())];
  const out = [...(surge.severity[i] ?? ZERO())];
  for (const c of sel.out) {
    const r = cnaRow(surge, c, i);
    if (r) for (let b = 0; b < out.length; b++) out[b] = Math.max(0, out[b] - r[b]);
  }
  return out;
}

// ── range and grouping ──

const mIndex = (m: string) => Number(m.slice(0, 4)) * 12 + Number(m.slice(5)) - 1;

export function bucketKey(month: string, group: Group): string {
  if (group === 'month') return month;
  if (group === 'year') return month.slice(0, 4);
  return `${month.slice(0, 4)}-Q${Math.floor((Number(month.slice(5)) - 1) / 3) + 1}`;
}

/** "Nov 2026", "Q4 2026" or "2026". */
export function bucketLabel(key: string, group: Group): string {
  if (group === 'month') return fmtMonth(key);
  if (group === 'year') return key;
  return `${key.slice(5)} ${key.slice(0, 4)}`;
}

/** First month of the bucket a month falls in. */
const bucketStart = (month: string, group: Group): string =>
  group === 'month' ? month : group === 'year' ? `${month.slice(0, 4)}-01` : shiftMonth(month, -((Number(month.slice(5)) - 1) % 3));

export interface Range {
  /** Inclusive month indices in `monthly`. */
  a: number;
  b: number;
  /** True when the view asks for a custom range (a drag or the month inputs). */
  custom: boolean;
}

/**
 * The months a view shows. Presets count back from the latest month, the partial one included. A
 * custom range is clamped to the data. With grouping, both ends widen to whole quarters or years, so
 * no bucket is cut short by the range.
 */
export function viewRange(monthly: readonly Month[], v: View): Range {
  const n = monthly.length;
  if (n === 0) return { a: 0, b: -1, custom: false };
  const first = monthly[0].month;
  const last = monthly[n - 1].month;
  const at = (m: string) => Math.min(n - 1, Math.max(0, mIndex(m) - mIndex(first)));
  const custom = v.from !== null || v.to !== null;
  let from: string;
  let to: string;
  if (custom) {
    from = v.from ?? first;
    to = v.to ?? last;
  } else {
    const len = PRESETS.find((p) => p.id === v.preset)?.months ?? null;
    to = last;
    from = len === null ? first : shiftMonth(last, 1 - len);
  }
  if (from < first) from = first;
  if (to > last) to = last;
  if (from > to) from = to;
  from = bucketStart(from, v.group);
  return { a: at(from < first ? first : from), b: Math.min(n - 1, at(to) + (v.group === 'month' ? 0 : bucketEndPad(to, v.group))), custom };
}

/** Months to add after `to` so it ends its quarter or year. */
function bucketEndPad(to: string, group: Group): number {
  const m = Number(to.slice(5));
  return group === 'year' ? 12 - m : group === 'quarter' ? (3 - (m % 3)) % 3 : 0;
}

// ── the series ──

export interface Point {
  key: string;
  label: string;
  /** First and last month in the bucket. */
  first: string;
  last: string;
  /** Holds the current, still-filling month. */
  partial: boolean;
  /** The main count: published (filtered) or reserved. */
  value: number;
  /** Severity split of `value`, in SEVERITY_BANDS order (zero for bands the filter leaves out). Null without surge.json or for Reserved. */
  bands: number[] | null;
  /** In CISA KEV, by publication month, with the same CNA and severity filters. Null without surge.json. */
  kevpub: number | null;
  /** Added to CISA KEV that period (by listing month); never filtered. */
  kevadd: number;
  /** AI-credited; never filtered. */
  ai: number;
  rejected: number;
  /**
   * The same period one year earlier, filtered the same way. For the partial bucket, its last month is
   * scaled to the share of that month elapsed, so it is the same point a year earlier. Null before 1999.
   */
  prev: number | null;
}

export interface Series {
  points: Point[];
  range: Range;
  progress: MonthProgress;
  /** surge.json is usable, so the filters work. */
  filtersReady: boolean;
  /** The view narrows the count with filters that apply right now. */
  narrowed: boolean;
}

export function buildSeries(monthly: readonly Month[], surgeFile: SurgeFile | null | undefined, v: View, generatedAt: string): Series {
  const surge = usableSurge(monthly, surgeFile);
  const idx = surge ? filterIndex(surge) : null;
  const sel = activeCnas(v, idx);
  const range = viewRange(monthly, v);
  const progress = monthProgress(monthly, generatedAt);
  const lastIdx = monthly.length - 1;
  const usePublishedSplit = v.count === 'published' && surge !== null && idx !== null;
  const narrowed = usePublishedSplit && (v.sev.length > 0 || sel.only !== null || sel.out.length > 0 || v.kev);
  const keep = (bands: number[]) => (v.sev.length ? bands.map((n, b) => (v.sev.includes(SEVERITY_BANDS[b]) ? n : 0)) : bands);
  const sum = (a: readonly number[]) => a.reduce((x, y) => x + y, 0);

  // Per month values, computed once.
  const cache = new Map<number, { value: number; bands: number[] | null; kevpub: number | null }>();
  const monthAt = (i: number) => {
    let c = cache.get(i);
    if (c) return c;
    const m = monthly[i];
    if (!usePublishedSplit) {
      c = { value: v.count === 'reserved' ? m.reserved : m.published, bands: null, kevpub: surge && idx ? sum(keep(monthBands(surge, idx, i, sel, true))) : null };
    } else {
      const bands = keep(monthBands(surge, idx, i, sel, v.kev));
      c = { value: narrowed ? sum(bands) : m.published, bands, kevpub: sum(keep(monthBands(surge, idx, i, sel, true))) };
    }
    cache.set(i, c);
    return c;
  };

  const points: Point[] = [];
  for (let i = range.a; i <= range.b; i++) {
    const m = monthly[i];
    const key = bucketKey(m.month, v.group);
    let p = points[points.length - 1];
    if (!p || p.key !== key) {
      p = { key, label: bucketLabel(key, v.group), first: m.month, last: m.month, partial: false, value: 0, bands: null, kevpub: null, kevadd: 0, ai: 0, rejected: 0, prev: 0 };
      points.push(p);
    }
    const c = monthAt(i);
    p.last = m.month;
    p.value += c.value;
    if (c.bands) p.bands = (p.bands ?? ZERO()).map((n, b) => n + c.bands![b]);
    if (c.kevpub !== null) p.kevpub = (p.kevpub ?? 0) + c.kevpub;
    p.kevadd += m.kev_added;
    p.ai += m.ai;
    p.rejected += m.rejected;
    const partial = progress.partial && i === lastIdx;
    if (partial) p.partial = true;
    const j = i - 12;
    if (p.prev !== null) {
      if (j < 0) p.prev = null;
      else {
        // The reserved count for recent months keeps growing for weeks, so its partial month has no fair comparison.
        const frac = partial ? (v.count === 'reserved' ? NaN : progress.daysInMonth > 0 ? progress.elapsed / progress.daysInMonth : 1) : 1;
        p.prev = Number.isNaN(frac) ? null : p.prev + monthAt(j).value * frac;
      }
    }
  }
  return { points, range, progress, filtersReady: surge !== null, narrowed };
}

/** now / then - 1 for a point, or null without a year-earlier value above zero. */
export function pointChange(p: Pick<Point, 'value' | 'prev'>): number | null {
  return p.prev !== null && p.prev > 0 ? p.value / p.prev - 1 : null;
}

// ── words and files ──

/** The filters in words, for the summary line, the CSV and the PNG: "Critical and High; excluding WordPress". */
export function filterWords(v: View, idx: FilterIndex | null): string {
  if (v.count === 'reserved' || !idx) return '';
  const parts: string[] = [];
  if (v.sev.length) parts.push(joinWords(SEVERITY_BANDS.filter((b) => v.sev.includes(b)).map((b) => BAND_LABELS[b])));
  const sel = activeCnas(v, idx);
  if (sel.only !== null) parts.push(`from ${idx.cnas[sel.only].label} only`);
  else if (sel.out.length) parts.push(`excluding ${joinWords(cnaGroupLabels(sel.out.map((i) => idx.cnas[i].key)))}`);
  if (v.kev) parts.push('in CISA KEV only');
  return parts.join('; ');
}

/** Name a whole WordPress or kernel group once, the way the quick toggles call it. */
function cnaGroupLabels(keys: readonly string[]): string[] {
  const out: string[] = [];
  const rest = new Set(keys);
  const present = (group: readonly string[]) => group.filter((k) => rest.has(k));
  const wp = present(WORDPRESS_CNAS);
  if (wp.length === WORDPRESS_CNAS.length) {
    out.push('WordPress plugin CNAs');
    wp.forEach((k) => rest.delete(k));
  }
  if (present(KERNEL_CNAS).length === KERNEL_CNAS.length) {
    out.push('the Linux kernel');
    KERNEL_CNAS.forEach((k) => rest.delete(k));
  }
  return [...out, ...[...rest].map((k) => cnaName(k))];
}

export function joinWords(words: readonly string[]): string {
  if (words.length <= 1) return words[0] ?? '';
  return `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
}

export interface CsvColumn {
  head: string;
  get: (p: Point) => number | string | null;
}

const csvCell = (v: number | string | null): string => {
  if (v === null) return '';
  if (typeof v === 'number') return String(Math.round(v));
  return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
};

/** The columns on screen, in the order the legend shows them. */
export function csvColumns(v: View, s: Pick<Series, 'narrowed' | 'filtersReady'>): CsvColumn[] {
  const cols: CsvColumn[] = [
    { head: 'period', get: (p) => p.key },
    { head: 'first_month', get: (p) => p.first },
    { head: 'last_month', get: (p) => p.last },
    { head: 'partial', get: (p) => (p.partial ? 'yes' : 'no') },
  ];
  const stacked = v.stack && v.count === 'published' && s.filtersReady;
  if (stacked) for (const [b, band] of SEVERITY_BANDS.entries()) if (!v.sev.length || v.sev.includes(band)) cols.push({ head: band, get: (p) => p.bands?.[b] ?? null });
  cols.push({ head: v.count, get: (p) => p.value });
  if (v.compare) cols.push({ head: `${v.count}_year_earlier`, get: (p) => p.prev });
  for (const o of visibleOverlays(v, s)) cols.push({ head: o === 'kevpub' ? 'in_kev_by_publication' : o === 'kevadd' ? 'added_to_kev' : 'ai_credited', get: (p) => (o === 'kevpub' ? p.kevpub : o === 'kevadd' ? p.kevadd : p.ai) });
  return cols;
}

/**
 * Which overlay lines show. The KEV additions and AI-credited lines count every CVE, so they hide
 * while a filter narrows the count; the in-KEV line follows the filters, and hides when the count is
 * already KEV only.
 */
export function visibleOverlays(v: View, s: Pick<Series, 'narrowed' | 'filtersReady'>): Overlay[] {
  return OVERLAYS.filter((o) => {
    if (!v.lines.includes(o)) return false;
    if (o === 'kevpub') return s.filtersReady && v.count === 'published' && !v.kev;
    return !s.narrowed;
  });
}

export function toCsv(points: readonly Point[], cols: readonly CsvColumn[]): string {
  const lines = [cols.map((c) => c.head).join(','), ...points.map((p) => cols.map((c) => csvCell(c.get(p))).join(','))];
  return `${lines.join('\r\n')}\r\n`;
}

/** "cverdict-cves-2024-01-to-2026-11-quarter.csv" */
export function exportName(points: readonly Point[], v: View, ext: 'csv' | 'png'): string {
  const a = points[0]?.first ?? 'none';
  const b = points[points.length - 1]?.last ?? 'none';
  return `cverdict-cves-${a}-to-${b}${v.group === 'month' ? '' : `-${v.group}`}.${ext}`;
}

/** The view after a drag across buckets i..j (either order): a custom range over their months. */
export function zoomTo(v: View, points: readonly Point[], i: number, j: number): View {
  const lo = Math.max(0, Math.min(i, j));
  const hi = Math.min(points.length - 1, Math.max(i, j));
  if (!points[lo] || !points[hi]) return v;
  return { ...v, from: points[lo].first, to: points[hi].last };
}

/** A preset clears any custom range. */
export const withPreset = (v: View, preset: Preset): View => ({ ...v, preset, from: null, to: null });

const SHORT_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/**
 * X axis labels: the smallest round step (in buckets) that keeps labels `minGap` px apart. Steps of a
 * year or more sit on years ("2025"); shorter ones on months or quarters ("Apr", "Q2"), with the
 * year on January or Q1 and on the first label.
 */
export function xTicks(points: readonly Pick<Point, 'key'>[], group: Group, px: number, minGap = 56): { i: number; label: string }[] {
  const n = points.length;
  if (n === 0) return [];
  if (n === 1) return [{ i: 0, label: bucketLabel(points[0].key, group) }];
  const per = px / (n - 1);
  const steps = group === 'month' ? [1, 2, 3, 6, 12, 24, 60, 120] : group === 'quarter' ? [1, 2, 4, 8, 20, 40] : [1, 2, 5, 10, 20];
  const yearly = group === 'month' ? 12 : group === 'quarter' ? 4 : 1;
  const step = steps.find((s) => s * per >= minGap) ?? steps[steps.length - 1];
  const out: { i: number; label: string }[] = [];
  points.forEach((p, i) => {
    const y = Number(p.key.slice(0, 4));
    const sub = group === 'month' ? Number(p.key.slice(5)) - 1 : group === 'quarter' ? Number(p.key.slice(6)) - 1 : 0;
    if (step >= yearly) {
      if (sub === 0 && y % (step / yearly) === 0) out.push({ i, label: String(y) });
      return;
    }
    if (sub % step !== 0) return;
    const name = group === 'month' ? SHORT_MONTHS[sub] : `Q${sub + 1}`;
    out.push({ i, label: sub === 0 || out.length === 0 ? `${name} ${y}` : name });
  });
  // A year label alone at a step of years can miss the range; fall back to the first bucket.
  if (!out.length) out.push({ i: 0, label: bucketLabel(points[0].key, group) });
  // Labels with a year are wider: drop any that would touch the one kept before it (about 6.5 px a character).
  const kept: { i: number; label: string }[] = [];
  for (const t of out) {
    const prev = kept[kept.length - 1];
    // The label at index 0 is drawn from its left edge (text-anchor start), so all of its width is to the right.
    const prevWidth = prev && prev.i === 0 ? prev.label.length * 6.5 : ((prev?.label.length ?? 0) * 6.5) / 2;
    if (prev && (t.i - prev.i) * per < prevWidth + (t.label.length * 6.5) / 2 + 10) continue;
    kept.push(t);
  }
  return kept;
}
