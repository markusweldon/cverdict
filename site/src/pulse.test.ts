import { describe, expect, it } from 'vitest';
import { EDGE_FADE, mergeRects, ringRegions, ringSpots, freshPerBin, freshSegs, HALO_R, haloSpots, mixColor, newLegend, parseColor, parseRgba, PULSE_PAD, PULSE_PERIOD_MS, pulseLevel, pulsePhase, pulseRegions, RING_R, RING_R0, RING_W, ringAt } from './pulse';

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

describe('ringAt', () => {
  const at = (k: number) => ringAt(pulsePhase(k * PULSE_PERIOD_MS));

  it('has no ring at the trough, so a paused or reduced-motion chart is the static one', () => {
    expect(ringAt(0).a).toBe(0);
    expect(at(0).a).toBe(0);
    expect(at(1).a).toBe(0);
    expect(at(5).a).toBe(0);
    expect(ringAt(1).a).toBe(0);
    expect(ringAt(Number.NaN).a).toBe(0);
    expect(pulsePhase(Number.NaN)).toBe(0);
  });

  it('starts at the tick as the beat rises and widens to about 28 px, slowing as it goes', () => {
    expect(at(0.001).r - RING_R0).toBeLessThan(0.1);
    expect(RING_R).toBeGreaterThanOrEqual(26);
    expect(RING_R).toBeLessThanOrEqual(30);
    expect(at(0.999).r).toBeCloseTo(RING_R, 3);
    let prev = 0;
    let step = Infinity;
    for (let k = 0.05; k < 1; k += 0.05) {
      const { r } = at(k);
      expect(r).toBeGreaterThan(prev);
      // An ease-out: each step outward is smaller than the one before.
      if (prev > 0) expect(r - prev).toBeLessThan(step + 1e-9);
      if (prev > 0) step = r - prev;
      prev = r;
    }
    expect(at(0.5).r).toBeGreaterThan(0.8 * RING_R);
  });

  it('fades in smoothly, then out all the way by the end of the beat, so rings never overlap', () => {
    expect(at(0.02).a).toBeLessThan(at(0.05).a);
    expect(at(0.05).a).toBeLessThan(at(0.1).a);
    // No hard flash: no 50 ms frame jumps the opacity by more than a quarter.
    const frame = 50 / PULSE_PERIOD_MS;
    for (let k = 0; k < 1; k += frame) expect(Math.abs(at(k + frame).a - at(k).a)).toBeLessThan(0.25);
    // Brightest early, then fading as it widens.
    for (let k = 0.15; k < 0.95; k += 0.05) expect(at(k + 0.05).a).toBeLessThan(at(k).a);
    expect(at(0.12).a).toBeGreaterThan(0.75);
    expect(at(0.5).a).toBeLessThan(0.4);
    expect(at(0.97).a).toBeLessThan(0.01);
    for (let k = 0; k < 1; k += 0.01) {
      expect(at(k).a).toBeGreaterThanOrEqual(0);
      expect(at(k).a).toBeLessThanOrEqual(1);
    }
  });

  it('is in phase with the halo: one ring per beat, starting at its trough', () => {
    expect(PULSE_PAD).toBeGreaterThanOrEqual(RING_R + RING_W / 2);
    expect(pulsePhase(PULSE_PERIOD_MS * 2.25)).toBeCloseTo(0.25, 12);
    expect(pulseLevel(0)).toBe(0);
    expect(ringAt(pulsePhase(0)).a).toBe(0);
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
      { cx: 11.5, cy: 101, r: HALO_R + 1, half: 1 },
      { cx: 41.5, cy: 48, r: HALO_R + 4, half: 4 },
    ]);
  });

  it('is a strong core about 32 to 40 px across for one tick, inside the repaint pad', () => {
    const [s] = haloSpots([{ x: 0, y: 0 }], 2, 2);
    expect(2 * s.r).toBeGreaterThanOrEqual(32);
    expect(2 * s.r).toBeLessThanOrEqual(40);
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
    // Stack 44..52: 10 above and below, 10 plus half the stack (4) to each side.
    expect(r).toEqual({ x: 26, y: 34, w: 31, h: 28 });
  });

  it('holds the whole ring and halo at their widest, for one tick and for a tall stack', () => {
    for (const n of [1, 6]) {
      const ticks = Array.from({ length: n }, (_, k) => ({ x: 200, y: 80 - 3 * k }));
      const [r] = pulseRegions(ticks, 3, 2, 400, 176);
      const [s] = haloSpots(ticks, 3, 2);
      const reach = Math.max(s.r, s.half + RING_R + RING_W / 2);
      expect(r.x).toBeLessThanOrEqual(s.cx - reach);
      expect(r.x + r.w).toBeGreaterThanOrEqual(s.cx + reach);
      expect(r.y).toBeLessThanOrEqual(s.cy - reach);
      expect(r.y + r.h).toBeGreaterThanOrEqual(s.cy + reach);
    }
    // One tick at 1x (half the stack is 1 px): about 67 by 64 px.
    const [one] = pulseRegions([{ x: 200, y: 80 }], 3, 2, 400, 176);
    expect(one).toEqual({ x: 200 - PULSE_PAD - 1, y: 80 - PULSE_PAD, w: 3 + 2 * (PULSE_PAD + 1), h: 2 + 2 * PULSE_PAD });
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
    expect(regions.map((r) => r.x)).toEqual([0, 398 - PULSE_PAD - 1]);
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
    expect(regions[0].x).toBe(90 - PULSE_PAD - 1);
  });
});

describe('newLegend', () => {
  it('names the count, 0 included, and a placeholder while loading', () => {
    expect(newLegend(3)).toBe('3 newly exploited');
    expect(newLegend(0)).toBe('0 newly exploited');
    expect(newLegend(null)).toBe('… newly exploited');
    expect(newLegend(1200)).toBe('1,200 newly exploited');
  });
});

describe('rings and edges', () => {
  it('gives neighbouring new columns one shared ring around both stacks', () => {
    const spots = haloSpots(
      [
        { x: 300, y: 60 },
        { x: 306, y: 54 },
        { x: 306, y: 57 },
        { x: 100, y: 80 },
      ],
      3,
      2,
    );
    const rings = ringSpots(spots);
    expect(rings).toHaveLength(2);
    expect(rings[0]).toEqual(spots[0]);
    const [, both] = rings;
    // The shared ring clears the far end of each stack.
    for (const s of spots.slice(1)) expect(both.half).toBeGreaterThanOrEqual(Math.hypot(s.cx - both.cx, s.cy - both.cy) + s.half - 1e-9);
    expect(both.cx).toBeCloseTo(304.5, 9);
    // Far apart columns keep their own rings.
    expect(ringSpots(haloSpots([{ x: 0, y: 80 }, { x: RING_R + 1, y: 80 }], 3, 2))).toHaveLength(2);
  });

  it('repaints a shared ring whole, once per pixel', () => {
    const ticks = [
      { x: 300, y: 60 },
      { x: 306, y: 60 },
    ];
    const rings = ringSpots(haloSpots(ticks, 3, 2));
    const regions = mergeRects([...pulseRegions(ticks, 3, 2, 400, 176), ...ringRegions(rings, 400, 176)]);
    expect(regions).toHaveLength(1);
    const [r] = regions;
    const [g] = rings;
    const reach = g.half + RING_R + RING_W / 2;
    expect(r.x).toBeLessThanOrEqual(g.cx - reach);
    expect(r.x + r.w).toBeGreaterThanOrEqual(g.cx + reach);
    expect(r.y).toBeLessThanOrEqual(g.cy - reach);
    expect(r.y + r.h).toBeGreaterThanOrEqual(g.cy + reach);
  });

  it('merges overlapping rects and leaves separate ones alone', () => {
    expect(
      mergeRects([
        { x: 50, y: 0, w: 10, h: 10 },
        { x: 0, y: 0, w: 10, h: 10 },
        { x: 5, y: 5, w: 10, h: 10 },
        { x: 14, y: 14, w: 2, h: 2 },
      ]),
    ).toEqual([
      { x: 0, y: 0, w: 16, h: 16 },
      { x: 50, y: 0, w: 10, h: 10 },
    ]);
  });

  it('clamps a tick 6 px from the right edge of a phone-width chart, which then fades instead of cutting', () => {
    const ticks = [{ x: 320 - 6 - 3, y: 80 }];
    const [r] = pulseRegions(ticks, 3, 2, 320, 176, 2);
    expect(r.x + r.w).toBe(320);
    const [ring] = ringRegions(ringSpots(haloSpots(ticks, 3, 2)), 320, 176, 2);
    expect(ring.x + ring.w).toBe(320);
    // The fade starts inside the ring's reach, so the ring thins out before it meets the edge.
    expect(EDGE_FADE).toBeGreaterThanOrEqual(8);
    expect(EDGE_FADE).toBeLessThan(RING_R);
  });
});
