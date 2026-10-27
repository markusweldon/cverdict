/**
 * Pure list logic shared by the feed, Explore, batches and the waterfall: tiers at the live knob,
 * search, and re-tiering of default-knob aggregates.
 */
import { SIGNAL_MIN_SCORE, TIERS, tierFor, type Row, type StatsFile, type Tier } from '../../shared/contract';
import { HOUR_MS } from './format';
import { isWatched } from './state';

export type TierCounts = Record<Tier, number>;

export const tierAt = (r: Row, knob: number): Tier => tierFor(r.s, r.x === 1, r.w === 1, knob);
export const isPassed = (t: Tier): boolean => t === 'exploited' || t === 'likely';
export const emptyCounts = (): TierCounts => ({ exploited: 0, likely: 0, watch: 0, quiet: 0 });

/**
 * Every chip that fired for a row, for filtering (`c` only holds the top four, for display).
 * Data published before the `r` column existed falls back to `c`.
 */
export const rowChips = (r: Row): readonly string[] => (Array.isArray(r.r) ? r.r : r.c);
export const hasChip = (r: Row, id: string): boolean => rowChips(r).includes(id);

const PUB_MS = new WeakMap<Row, number>();
/** `pub` as epoch ms, parsed once per row: the feed and the waterfall re-read it on every knob step. */
export function pubMs(r: Row): number {
  let t = PUB_MS.get(r);
  if (t === undefined) PUB_MS.set(r, (t = Date.parse(r.pub)));
  return t;
}

export const WORDPRESS_CNAS: readonly string[] = ['Wordfence', 'WPScan', 'Patchstack'];
export const isWordpress = (r: Row): boolean => WORDPRESS_CNAS.includes(r.cna) || hasChip(r, 'noise.wordpress');
export const isKernel = (r: Row): boolean => r.cna === 'Linux' || hasChip(r, 'noise.kernel');

export function countTiers(rows: readonly Row[], knob: number): TierCounts {
  const out = emptyCounts();
  for (const r of rows) out[tierAt(r, knob)]++;
  return out;
}

/**
 * Re-tier counts computed at the default knob (stats, batches) for another knob, using only the
 * rows in the group that can move: the signal rows. Exact for knob ≥ SIGNAL_MIN_SCORE, because
 * every row that is Likely at such a knob is in signal.json and Watch + Likely is knob-invariant.
 */
export function retier(defaults: TierCounts, signalRows: readonly Row[], knob: number): TierCounts {
  let delta = 0;
  for (const r of signalRows) {
    if (tierAt(r, knob) === 'likely') delta++;
    if (r.tier === 'likely') delta--;
  }
  const likely = Math.max(0, defaults.likely + delta);
  return { exploited: defaults.exploited, likely, watch: Math.max(0, defaults.watch + defaults.likely - likely), quiet: defaults.quiet };
}

/** Rows grouped by batch id. */
export function groupByBatch(rows: readonly Row[]): Map<string, Row[]> {
  const m = new Map<string, Row[]>();
  for (const r of rows) {
    if (!r.b) continue;
    const list = m.get(r.b);
    if (list) list.push(r);
    else m.set(r.b, [r]);
  }
  return m;
}

/**
 * A batch's tier counts at `knob`. With every window row loaded (`complete`) its members are
 * recounted; otherwise its default-knob counts are re-tiered from the signal members, which is
 * only exact for knob ≥ SIGNAL_MIN_SCORE.
 */
export function batchCounts(defaults: TierCounts, members: readonly Row[], knob: number, complete: boolean): { counts: TierCounts; exact: boolean } {
  if (complete) return { counts: countTiers(members, knob), exact: true };
  return { counts: retier(defaults, members, knob), exact: knob >= SIGNAL_MIN_SCORE };
}

export type HourCounts = [exploited: number, likely: number, watch: number, quiet: number];

/**
 * Waterfall buckets at `knob`. With every window row (`complete`), counts are recomputed exactly;
 * with signal rows only, the default-knob buckets from stats.json are re-tiered per hour.
 */
export function hourlyAt(hourly: StatsFile['hourly'], rows: readonly Row[], knob: number, complete: boolean): HourCounts[] {
  const start = Date.parse(hourly.start);
  const n = hourly.counts.length;
  const bucket = (r: Row) => Math.floor((pubMs(r) - start) / HOUR_MS);
  if (complete) {
    const out: HourCounts[] = Array.from({ length: n }, () => [0, 0, 0, 0]);
    for (const r of rows) {
      const i = bucket(r);
      if (i >= 0 && i < n) out[i][TIERS.indexOf(tierAt(r, knob))]++;
    }
    return out;
  }
  const delta = new Int32Array(n);
  for (const r of rows) {
    const i = bucket(r);
    if (i < 0 || i >= n) continue;
    if (tierAt(r, knob) === 'likely') delta[i]++;
    if (r.tier === 'likely') delta[i]--;
  }
  return hourly.counts.map(([e, l, w, q], i) => {
    const likely = Math.max(0, l + delta[i]);
    return [e, likely, Math.max(0, w + l - likely), q];
  });
}

/** Lower-cased search terms; every term must match. */
export const terms = (q: string): string[] => q.toLowerCase().split(/\s+/).filter(Boolean);

export function matches(r: Row, ts: readonly string[]): boolean {
  if (ts.length === 0) return true;
  const hay = `${r.id} ${r.v} ${r.p} ${r.t} ${r.cna}`.toLowerCase();
  return ts.every((t) => hay.includes(t));
}

export interface FeedFilter {
  tiers: ReadonlySet<Tier>;
  query: string;
  hideWordpress: boolean;
  hideKernel: boolean;
  hideAi: boolean;
  watchOnly: boolean;
  chip: string | null;
}

export interface FeedRow {
  row: Row;
  tier: Tier;
  watched: boolean;
}

/**
 * The Today feed: rows in the selected tiers at the knob, plus watched rows regardless of the
 * knob (watched items bypass it), minus the noise the viewer chose to hide.
 */
export function feedRows(rows: readonly Row[], f: FeedFilter, knob: number, watch: readonly string[]): FeedRow[] {
  const ts = terms(f.query);
  const out: FeedRow[] = [];
  for (const row of rows) {
    const tier = tierAt(row, knob);
    const watched = isWatched(watch, row);
    if (f.watchOnly ? !watched : !(f.tiers.has(tier) || watched)) continue;
    if (f.hideWordpress && isWordpress(row)) continue;
    if (f.hideKernel && isKernel(row)) continue;
    if (f.hideAi && row.ai === 1) continue;
    if (f.chip && !hasChip(row, f.chip)) continue;
    if (!matches(row, ts)) continue;
    out.push({ row, tier, watched });
  }
  return out;
}

const DEFAULT_FEED_TIERS: readonly Tier[] = ['exploited', 'likely'];
export const DEFAULT_FEED_FILTER: FeedFilter = { tiers: new Set(DEFAULT_FEED_TIERS), query: '', hideWordpress: false, hideKernel: false, hideAi: false, watchOnly: false, chip: null };

/** URL parameters that hold the Today feed filter. */
export const FEED_PARAMS = ['tier', 'q', 'hide', 'only', 'chip'] as const;

/** The feed filter kept in the URL, so Back (and a shared link) restores it. Missing parameters mean the defaults. */
export function readFeedFilter(search: URLSearchParams): FeedFilter {
  const tier = search.get('tier');
  const hide = (search.get('hide') ?? '').split(',');
  return {
    tiers: tier === null ? new Set(DEFAULT_FEED_TIERS) : new Set(tier.split(',').filter((t): t is Tier => (TIERS as readonly string[]).includes(t))),
    query: search.get('q') ?? '',
    hideWordpress: hide.includes('wordpress'),
    hideKernel: hide.includes('kernel'),
    hideAi: hide.includes('ai'),
    watchOnly: search.get('only') === 'watchlist',
    chip: search.get('chip') || null,
  };
}

/** The inverse of readFeedFilter, for setQuery (null deletes a parameter). Defaults stay out of the URL. */
export function feedFilterQuery(f: FeedFilter): Record<(typeof FEED_PARAMS)[number], string | null> {
  const tiers = TIERS.filter((t) => f.tiers.has(t));
  const isDefault = tiers.length === DEFAULT_FEED_TIERS.length && DEFAULT_FEED_TIERS.every((t) => f.tiers.has(t));
  const hide = [f.hideWordpress && 'wordpress', f.hideKernel && 'kernel', f.hideAi && 'ai'].filter(Boolean).join(',');
  return { tier: isDefault ? null : tiers.join(',') || 'none', q: f.query.trim() || null, hide: hide || null, only: f.watchOnly ? 'watchlist' : null, chip: f.chip };
}

const TIER_RANK: Readonly<Record<Tier, number>> = { exploited: 3, likely: 2, watch: 1, quiet: 0 };

/** Score desc, then newest — the order signal.json ships in, re-applied after merging sources. */
export function byScore(a: FeedRow, b: FeedRow): number {
  return TIER_RANK[b.tier] - TIER_RANK[a.tier] || b.row.s - a.row.s || b.row.pub.localeCompare(a.row.pub);
}
