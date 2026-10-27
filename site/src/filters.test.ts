import { describe, expect, it } from 'vitest';
import { KNOB_DEFAULT, KNOB_MAX, SIGNAL_MIN_SCORE, TIERS, tierFor, type Row } from '../../shared/contract';
import {
  batchCounts,
  byScore,
  countTiers,
  DEFAULT_FEED_FILTER,
  feedFilterQuery,
  feedRows,
  groupByBatch,
  hasChip,
  hourlyAt,
  isWordpress,
  matches,
  pubMs,
  readFeedFilter,
  retier,
  rowChips,
  terms,
  tierAt,
  type FeedFilter,
} from './filters';

const START = Date.parse('2026-09-26T19:00:00Z');

function mkRow(i: number, s: number, opts: Partial<Row> = {}): Row {
  const x = opts.x ?? 0;
  const w = opts.w ?? 0;
  const row: Omit<Row, 'r'> = {
    id: `CVE-2026-${10_000 + i}`,
    pub: new Date(START + (i % 48) * 3_600_000 + 60_000).toISOString(),
    cna: 'VulnCheck',
    v: 'Acme',
    p: 'Widget',
    t: `Widget bug ${i}`,
    s,
    tier: tierFor(s, x === 1, w === 1, KNOB_DEFAULT),
    x,
    w,
    k: 0,
    ai: 0,
    c: [],
    cv: null,
    e: null,
    kd: null,
    b: null,
    ...opts,
  };
  // Every chip that fired: at least the display chips.
  return { ...row, r: opts.r ?? row.c };
}

/** Deterministic pseudo-random rows covering every tier and the knob range. */
function corpus(n = 600): Row[] {
  let seed = 7;
  const r = () => ((seed = (seed * 1_103_515_245 + 12_345) % 2 ** 31) / 2 ** 31);
  return Array.from({ length: n }, (_, i) => mkRow(i, Math.floor(r() * 101), { x: r() < 0.03 ? 1 : 0, w: r() < 0.04 ? 1 : 0 }));
}

const signalOf = (rows: Row[]) => rows.filter((r) => r.s >= SIGNAL_MIN_SCORE || r.x || r.w);

describe('re-tiering from signal rows', () => {
  const rows = corpus();
  const defaults = countTiers(rows, KNOB_DEFAULT);

  it('matches a full recount for every knob ≥ the signal floor', () => {
    for (let knob = SIGNAL_MIN_SCORE; knob <= KNOB_MAX; knob++) {
      expect(retier(defaults, signalOf(rows), knob)).toEqual(countTiers(rows, knob));
    }
  });

  it('counts batches exactly from every row, and flags the signal-only estimate below 35', () => {
    const all = rows.map((r, i) => ({ ...r, b: i % 3 === 0 ? 'acme-2026-10-13' : null }));
    const members = groupByBatch(all).get('acme-2026-10-13')!;
    expect(members).toHaveLength(all.filter((r) => r.b).length);
    expect(groupByBatch(all).size).toBe(1);
    const defaults = countTiers(members, KNOB_DEFAULT);
    for (const knob of [30, 34, 35, 50, 80]) {
      expect(batchCounts(defaults, members, knob, true)).toEqual({ counts: countTiers(members, knob), exact: true });
      const estimate = batchCounts(defaults, signalOf(members), knob, false);
      expect(estimate.exact).toBe(knob >= SIGNAL_MIN_SCORE);
      if (estimate.exact) expect(estimate.counts).toEqual(countTiers(members, knob));
    }
  });

  it('does the same per hour for the waterfall', () => {
    const counts: [number, number, number, number][] = Array.from({ length: 48 }, () => [0, 0, 0, 0]);
    for (const r of rows) counts[Math.floor((Date.parse(r.pub) - START) / 3_600_000)][TIERS.indexOf(r.tier)]++;
    const hourly = { start: new Date(START).toISOString(), hours: 48, counts };
    for (const knob of [35, 42, 50, 60, 80]) {
      expect(hourlyAt(hourly, signalOf(rows), knob, false)).toEqual(hourlyAt(hourly, rows, knob, true));
    }
    expect(hourlyAt(hourly, rows, KNOB_DEFAULT, true)).toEqual(counts);
  });

  it('keeps exploited and weaponized rows in their tiers at any knob', () => {
    expect(tierAt(mkRow(1, 0, { x: 1 }), 80)).toBe('exploited');
    expect(tierAt(mkRow(2, 10, { w: 1 }), 80)).toBe('likely');
    expect(tierAt(mkRow(3, 24), 30)).toBe('quiet');
  });
});

describe('row chips', () => {
  it('reads r, falling back to c for data published before r existed', () => {
    const row = mkRow(1, 50, { c: ['x.poc'], r: ['x.poc', 'epss.mid'] });
    expect(rowChips(row)).toEqual(['x.poc', 'epss.mid']);
    expect(hasChip(row, 'epss.mid')).toBe(true);
    const old = { ...row, r: undefined } as unknown as Row;
    expect(rowChips(old)).toEqual(['x.poc']);
    expect(hasChip(old, 'epss.mid')).toBe(false);
  });

  it('parses pub once per row', () => {
    const row = mkRow(1, 50);
    expect(pubMs(row)).toBe(Date.parse(row.pub));
    expect(pubMs(row)).toBe(pubMs(row));
  });
});

describe('feed filter in the URL', () => {
  it('keeps defaults out of the URL and round-trips everything else', () => {
    expect(feedFilterQuery(DEFAULT_FEED_FILTER)).toEqual({ tier: null, q: null, hide: null, only: null, chip: null });
    expect(readFeedFilter(new URLSearchParams(''))).toEqual(DEFAULT_FEED_FILTER);
    const f: FeedFilter = { tiers: new Set(['likely', 'watch']), query: ' fortinet ', hideWordpress: true, hideKernel: false, hideAi: true, watchOnly: true, chip: 'x.poc' };
    const q = feedFilterQuery(f);
    expect(q).toEqual({ tier: 'likely,watch', q: 'fortinet', hide: 'wordpress,ai', only: 'watchlist', chip: 'x.poc' });
    const params = new URLSearchParams(Object.entries(q).filter((e): e is [string, string] => e[1] !== null));
    expect(readFeedFilter(params)).toEqual({ ...f, query: 'fortinet' });
  });

  it('distinguishes no tiers from the default tiers, and ignores junk', () => {
    const none = { ...DEFAULT_FEED_FILTER, tiers: new Set<never>() };
    expect(feedFilterQuery(none).tier).toBe('none');
    expect(readFeedFilter(new URLSearchParams('tier=none')).tiers.size).toBe(0);
    expect([...readFeedFilter(new URLSearchParams('tier=bogus,exploited&hide=x')).tiers]).toEqual(['exploited']);
  });
});

describe('search', () => {
  it('requires every term to match ID, vendor, product, title or CNA', () => {
    const r = mkRow(1, 50, { v: 'Fortinet', p: 'FortiOS', t: 'Heap overflow in sslvpnd' });
    expect(matches(r, terms('fortinet SSLVPN'))).toBe(true);
    expect(matches(r, terms('cve-2026-10001'))).toBe(true);
    expect(matches(r, terms('fortinet ivanti'))).toBe(false);
    expect(matches(r, terms('   '))).toBe(true);
  });
});

describe('feedRows', () => {
  const base: FeedFilter = { tiers: new Set(['exploited', 'likely']), query: '', hideWordpress: false, hideKernel: false, hideAi: false, watchOnly: false, chip: null };
  const rows = [
    mkRow(1, 95, { x: 1, c: ['kev.listed'] }),
    mkRow(2, 60, { c: ['x.poc'] }),
    mkRow(3, 40, { cna: 'Wordfence', c: ['noise.wordpress'] }),
    mkRow(4, 55, { cna: 'Linux', v: 'Linux', p: 'Linux' }),
    mkRow(5, 70, { ai: 1 }),
    mkRow(6, 5, { v: 'Ivanti', p: 'Connect Secure' }),
  ];
  const ids = (f: FeedFilter, knob = KNOB_DEFAULT, watch: string[] = []) => feedRows(rows, f, knob, watch).map((r) => r.row.id.slice(-2));

  it('shows the passed tiers at the knob', () => {
    expect(ids(base)).toEqual(['01', '02', '04', '05']);
    expect(ids(base, 60)).toEqual(['01', '02', '05']);
    expect(ids({ ...base, tiers: new Set(['watch']) })).toEqual(['03']);
  });

  it('lets watched vendors bypass the knob, or show alone', () => {
    expect(ids(base, KNOB_DEFAULT, ['ivanti'])).toContain('06');
    expect(ids({ ...base, watchOnly: true }, KNOB_DEFAULT, ['ivanti'])).toEqual(['06']);
    expect(feedRows(rows, base, KNOB_DEFAULT, ['connect secure']).find((r) => r.row.id.endsWith('06'))?.watched).toBe(true);
  });

  it('hides noise on request and filters by chip', () => {
    const all = { ...base, tiers: new Set(['exploited', 'likely', 'watch'] as const) };
    expect(ids({ ...all, hideWordpress: true })).not.toContain('03');
    expect(ids({ ...all, hideKernel: true })).not.toContain('04');
    expect(ids({ ...all, hideAi: true })).not.toContain('05');
    expect(ids({ ...all, chip: 'x.poc' })).toEqual(['02']);
  });

  it('filters by every chip that fired, not only the four on display', () => {
    const lost = mkRow(7, 95, { x: 1, c: ['kev.listed', 'x.nuclei', 'prior.product', 'ssvc.automatable'], r: ['kev.listed', 'ssvc.active', 'x.nuclei', 'prior.product', 'ssvc.automatable', 'noise.wordpress'] });
    const f = { ...base, chip: 'ssvc.active' };
    expect(feedRows([...rows, lost], f, KNOB_DEFAULT, []).map((r) => r.row.id)).toEqual([lost.id]);
    expect(isWordpress(lost)).toBe(true);
  });

  it('sorts by tier, then score, then newest', () => {
    const sorted = feedRows(rows, { ...base, tiers: new Set(TIERS) }, KNOB_DEFAULT, []).sort(byScore).map((r) => r.row.id.slice(-2));
    expect(sorted).toEqual(['01', '05', '02', '04', '03', '06']);
  });
});
