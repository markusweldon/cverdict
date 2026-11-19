import { describe, expect, it } from 'vitest';
import { freshPerBin, freshSegs, HALO_R, haloSpots, mixColor, newLegend, parseColor, parseRgba, PULSE_PAD, PULSE_PERIOD_MS, pulseLevel, pulseRegions } from './pulse';

describe('pulseLevel', () => {
  it('is 0 at the trough, so a paused chart is the static one', () => {
    expect(pulseLevel(0)).toBe(0);
    expect(pulseLevel(PULSE_PERIOD_MS)).toBe(0);
    expect(pulseLevel(3 * PULSE_PERIOD_MS)).toBe(0);
  });

  it('peaks at 1 halfway through the period', () => {
    expect(pulseLevel(PULSE_PERIOD_MS / 2)).toBeCloseTo(1, 12);
  });

  it('eases in and out like a sine, symmetric around the peak', () => {
    expect(pulseLevel(PULSE_PERIOD_MS / 4)).toBeCloseTo(0.5, 12);
    expect(pulseLevel(PULSE_PERIOD_MS * 0.1)).toBeCloseTo(pulseLevel(PULSE_PERIOD_MS * 0.9), 12);
    // Slow at the ends: the first tenth of the rise covers far less than a tenth of the height.
    expect(pulseLevel(PULSE_PERIOD_MS * 0.05)).toBeLessThan(0.05);
  });

  it('repeats every period and stays within 0..1', () => {
    for (let t = 0; t < PULSE_PERIOD_MS; t += 97) {
      const v = pulseLevel(t);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
      expect(pulseLevel(t + 2 * PULSE_PERIOD_MS)).toBeCloseTo(v, 9);
    }
  });

  it('uses a slow, calm period', () => {
    expect(PULSE_PERIOD_MS).toBeGreaterThanOrEqual(2600);
    expect(PULSE_PERIOD_MS).toBeLessThanOrEqual(3000);
    expect(pulseLevel(500, 1000)).toBeCloseTo(1, 12);
  });

  it('reads bad input as the trough', () => {
    expect(pulseLevel(Number.NaN)).toBe(0);
    expect(pulseLevel(100, 0)).toBe(0);
    expect(pulseLevel(-PULSE_PERIOD_MS / 2)).toBeCloseTo(1, 12);
  });
});

describe('colours', () => {
  it('parses the forms a canvas and the tokens use', () => {
    expect(parseColor('#ff4d4f')).toEqual([255, 77, 79]);
    expect(parseColor('#f00')).toEqual([255, 0, 0]);
    expect(parseColor('rgb(217, 45, 32)')).toEqual([217, 45, 32]);
    expect(parseColor('rgba(1, 2, 3, 0.5)')).toEqual([1, 2, 3]);
    expect(parseColor('oklch(0.6 0.2 30)')).toBeNull();
  });

  it('keeps the alpha for the halo token', () => {
    expect(parseRgba('rgb(255 77 79 / 0.6)')).toEqual([255, 77, 79, 0.6]);
    expect(parseRgba('rgba(217, 45, 32, 0.42)')).toEqual([217, 45, 32, 0.42]);
    expect(parseRgba('rgb(1 2 3 / 50%)')).toEqual([1, 2, 3, 0.5]);
    expect(parseRgba('#ff4d4f')).toEqual([255, 77, 79, 1]);
    expect(parseRgba('#ff000080')?.[3]).toBeCloseTo(128 / 255, 9);
    expect(parseRgba('rgb(1 2 3 / 3)')?.[3]).toBe(1);
    expect(parseRgba('nope')).toBeNull();
  });

  it('mixes from the static colour at 0 to the peak colour at 1', () => {
    expect(mixColor([255, 77, 79], [255, 160, 146], 0)).toBe('rgb(255, 77, 79)');
    expect(mixColor([255, 77, 79], [255, 160, 146], 1)).toBe('rgb(255, 160, 146)');
    expect(mixColor([0, 0, 0], [200, 100, 50], 0.5)).toBe('rgb(100, 50, 25)');
    expect(mixColor([0, 0, 0], [200, 100, 50], 2)).toBe('rgb(200, 100, 50)');
  });
});

describe('haloSpots', () => {
  it('centres one halo per column on its exploited stack', () => {
    const spots = haloSpots(
      [
        { x: 40, y: 50 },
        { x: 40, y: 44 },
        { x: 10, y: 100 },
      ],
      3,
      2,
    );
    expect(spots).toEqual([
      { cx: 11.5, cy: 101, r: HALO_R + 1 },
      { cx: 41.5, cy: 48, r: HALO_R + 4 },
    ]);
  });

  it('covers far more than the tick itself, and fits inside the repaint pad', () => {
    const [s] = haloSpots([{ x: 0, y: 0 }], 2, 2);
    expect(2 * s.r).toBeGreaterThanOrEqual(16);
    expect(PULSE_PAD).toBeGreaterThanOrEqual(HALO_R);
  });

  it('is empty without exploited ticks', () => {
    expect(haloSpots([], 3, 2)).toEqual([]);
  });
});

describe('pulseRegions', () => {
  it('gives one padded rect per column around its stacked ticks', () => {
    const ticks = [
      { x: 40, y: 50 },
      { x: 40, y: 47 },
      { x: 40, y: 44 },
    ];
    const [r, ...rest] = pulseRegions(ticks, 3, 2, 400, 176, 1, 10);
    expect(rest).toEqual([]);
    expect(r).toEqual({ x: 30, y: 34, w: 23, h: 28 });
  });

  it('sorts columns and clamps to the canvas', () => {
    const regions = pulseRegions(
      [
        { x: 398, y: 100 },
        { x: 1, y: 2 },
      ],
      2,
      2,
      400,
      176,
    );
    expect(regions.map((r) => r.x)).toEqual([0, 398 - PULSE_PAD]);
    expect(regions[0].y).toBe(0);
    expect(regions[1].x + regions[1].w).toBe(400);
  });

  it('snaps outward to whole device pixels', () => {
    const [r] = pulseRegions([{ x: 10.3, y: 20.2 }], 2.4, 2, 400, 176, 2, 1);
    for (const v of [r.x, r.y, r.x + r.w, r.y + r.h]) expect(Number.isInteger(v * 2)).toBe(true);
    expect(r.x).toBeLessThanOrEqual(9.3);
    expect(r.x + r.w).toBeGreaterThanOrEqual(13.7);
  });

  it('is empty without exploited ticks', () => {
    expect(pulseRegions([], 3, 2, 400, 176)).toEqual([]);
  });
});

describe('only newly exploited ticks pulse', () => {
  const bin = (hours: number, exploited: number) => ({ hours, c: [exploited, 0, 0, 0] });

  it('sums the per-hour counts over each column and caps them at its exploited count', () => {
    const fresh = [0, 1, 0, 0, 2, 0, 0, 5];
    expect(freshPerBin(fresh, [bin(3, 4), bin(3, 1), bin(2, 9)])).toEqual([1, 1, 5]);
    // A short last column, and hours past the end of `fresh`, add nothing.
    expect(freshPerBin([0, 0, 1], [bin(2, 1), bin(2, 1)])).toEqual([0, 1]);
  });

  it('is empty without newly exploited CVEs, so nothing pulses', () => {
    expect(freshPerBin([], [bin(3, 4)])).toEqual([]);
  });

  it('marks the top ticks of the exploited stack in proportion, at least one, all only when all are new', () => {
    expect(freshSegs(4, 8, 0)).toBe(0);
    expect(freshSegs(4, 8, 2)).toBe(1);
    expect(freshSegs(4, 8, 1)).toBe(1);
    expect(freshSegs(4, 8, 6)).toBe(3);
    expect(freshSegs(4, 8, 7)).toBe(3);
    expect(freshSegs(4, 8, 8)).toBe(4);
    expect(freshSegs(1, 3, 1)).toBe(1);
    expect(freshSegs(0, 3, 1)).toBe(0);
    expect(freshSegs(3, 0, 1)).toBe(0);
  });

  it('repaints regions only around columns with new ticks', () => {
    // Two exploited columns, one with a new CVE: as Waterfall.tsx picks them, the top tick of column 1 only.
    const cols = [
      { x: 30, exploited: 2, segs: 2 },
      { x: 90, exploited: 3, segs: 3 },
    ];
    const perCol = freshPerBin([0, 0, 0, 1], [bin(2, 2), bin(2, 3)]);
    const ticks = cols.flatMap((c, i) => {
      const f = freshSegs(c.segs, c.exploited, perCol[i]);
      return Array.from({ length: c.segs }, (_, s) => ({ x: c.x, y: 100 - s * 3, fresh: s >= c.segs - f })).filter((t) => t.fresh);
    });
    expect(ticks).toEqual([{ x: 90, y: 94, fresh: true }]);
    const regions = pulseRegions(ticks, 2, 2, 400, 176);
    expect(regions).toHaveLength(1);
    expect(regions[0].x).toBe(90 - PULSE_PAD);
  });
});

describe('newLegend', () => {
  it('names the count, 0 included, and a placeholder while loading', () => {
    expect(newLegend([0, 2, 0, 1])).toBe('New in 72h: 3');
    expect(newLegend([0, 0])).toBe('New in 72h: 0');
    expect(newLegend([])).toBe('New in 72h: 0');
    expect(newLegend(null)).toBe('New in 72h: …');
    expect(newLegend([1200])).toBe('New in 72h: 1,200');
  });
});
