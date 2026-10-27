/**
 * Pure list logic shared by the feed, Explore, batches and the waterfall: tiers at the live knob,
 * search, and re-tiering of default-knob aggregates.
 */
import { TIERS, tierFor, type Row, type StatsFile, type Tier } from '../../shared/contract';
import { HOUR_MS } from './format';
import { isWatched } from './state';

export type TierCounts = Record<Tier, number>;

export const tierAt = (r: Row, knob: number): Tier => tierFor(r.s, r.x === 1, r.w === 1, knob);
export const isPassed = (t: Tier): boolean => t === 'exploited' || t === 'likely';
export const emptyCounts = (): TierCounts => ({ exploited: 0, likely: 0, watch: 0, quiet: 0 });

export const WORDPRESS_CNAS: readonly string[] = ['Wordfence', 'WPScan', 'Patchstack'];
export const isWordpress = (r: Row): boolean => WORDPRESS_CNAS.includes(r.cna) || r.c.includes('noise.wordpress');
export const isKernel = (r: Row): boolean => r.cna === 'Linux' || r.c.includes('noise.kernel');

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

export type HourCounts = [exploited: number, likely: number, watch: number, quiet: number];

/**
 * Waterfall buckets at `knob`. With every window row (`complete`), counts are recomputed exactly;
 * with signal rows only, the default-knob buckets from stats.json are re-tiered per hour.
 */
export function hourlyAt(hourly: StatsFile['hourly'], rows: readonly Row[], knob: number, complete: boolean): HourCounts[] {
  const start = Date.parse(hourly.start);
  const n = hourly.counts.length;
  const bucket = (r: Row) => Math.floor((Date.parse(r.pub) - start) / HOUR_MS);
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
    if (f.chip && !row.c.includes(f.chip)) continue;
    if (!matches(row, ts)) continue;
    out.push({ row, tier, watched });
  }
  return out;
}

const TIER_RANK: Readonly<Record<Tier, number>> = { exploited: 3, likely: 2, watch: 1, quiet: 0 };

/** Score desc, then newest — the order signal.json ships in, re-applied after merging sources. */
export function byScore(a: FeedRow, b: FeedRow): number {
  return TIER_RANK[b.tier] - TIER_RANK[a.tier] || b.row.s - a.row.s || b.row.pub.localeCompare(a.row.pub);
}
