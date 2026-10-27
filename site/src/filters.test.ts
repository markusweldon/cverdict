import { describe, expect, it } from 'vitest';
import { KNOB_DEFAULT, KNOB_MAX, SIGNAL_MIN_SCORE, TIERS, tierFor, type Row } from '../../shared/contract';
import { byScore, countTiers, feedRows, hourlyAt, matches, retier, terms, tierAt, type FeedFilter } from './filters';

const START = Date.parse('2026-09-26T19:00:00Z');

function mkRow(i: number, s: number, opts: Partial<Row> = {}): Row {
  const x = opts.x ?? 0;
  const w = opts.w ?? 0;
  return {
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

  it('sorts by tier, then score, then newest', () => {
    const sorted = feedRows(rows, { ...base, tiers: new Set(TIERS) }, KNOB_DEFAULT, []).sort(byScore).map((r) => r.row.id.slice(-2));
    expect(sorted).toEqual(['01', '05', '02', '04', '03', '06']);
  });
});
