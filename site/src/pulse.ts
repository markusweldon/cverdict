/**
 * The exploited-tick pulse on the signal waterfall. Only CVEs that became Exploited in the last
 * 72 hours (stats.json hourly.new_exploited) pulse, like a contact on a radar: each beat a thin
 * red ring leaves the ticks and fades as it widens, while a soft red halo swells behind them and
 * the ticks shift toward a stronger red, all in phase. The ticks are only about 2x2 px, so the
 * halo and the ring carry the visible change. Both sit behind the chart, so no other tick changes
 * colour. Pure helpers live here so they can be tested without a canvas; Waterfall.tsx owns the
 * timer and the drawing.
 */
import { fmtInt } from './format';

/** One full breath (trough to peak and back), in ms. */
export const PULSE_PERIOD_MS = 2800;
/** Time between pulse frames: about 20 fps, which is plenty for a change this slow. */
export const PULSE_FRAME_MS = 50;
/** Halo radius around a column's exploited ticks, in CSS px (so about 36px across for one tick). */
export const HALO_R = 17;
/** How far the ring travels past the ends of a column's exploited stack, in CSS px. */
export const RING_R = 28;
/** Where the ring starts, past the ends of the stack: just outside the ticks. */
export const RING_R0 = 1.5;
/** Ring stroke width, in CSS px. */
export const RING_W = 1.5;
/** Room kept around each column for its halo and ring, so a repaint never cuts either off. */
export const PULSE_PAD = Math.ceil(Math.max(HALO_R, RING_R + RING_W / 2)) + 2;
/**
 * The halo and the ring fade out over this many CSS px before an edge of the canvas, so a column
 * near the edge (the newest ones sit at the right) never shows a flat cut through either.
 */
export const EDGE_FADE = 10;

/**
 * Pulse level for a time since the pulse started: 0 at the trough (the static colour), 1 at the
 * peak, eased in and out by a sine. Starts and ends each period at 0.
 */
export function pulseLevel(elapsedMs: number, periodMs = PULSE_PERIOD_MS): number {
  if (!(periodMs > 0) || !Number.isFinite(elapsedMs)) return 0;
  const phase = pulsePhase(elapsedMs, periodMs);
  const v = (1 - Math.cos(2 * Math.PI * phase)) / 2;
  // Snap the float residue at the trough so level 0 really means "draw nothing".
  return v < 1e-9 ? 0 : v;
}

/** Phase within the beat, 0 at the trough up to (not including) 1. */
export function pulsePhase(elapsedMs: number, periodMs = PULSE_PERIOD_MS): number {
  if (!(periodMs > 0) || !Number.isFinite(elapsedMs)) return 0;
  return (((elapsedMs % periodMs) + periodMs) % periodMs) / periodMs;
}

export interface Ring {
  /** Distance past the ends of the stack, CSS px. */
  r: number;
  /** Opacity factor 0..1, multiplied by the ring colour's own alpha. */
  a: number;
}

/**
 * The ring for a phase of the beat: it leaves the ticks as the beat rises, slows as it widens
 * (an ease-out, like a sonar return) and fades all the way, so one ring ends before the next
 * starts. Its opacity eases in over the first eighth or so (no hard flash) and is exactly 0 at the
 * trough, so a paused chart shows no ring.
 */
export function ringAt(phase: number): Ring {
  if (!(phase > 0) || !(phase < 1)) return { r: RING_R0, a: 0 };
  const grow = 1 - Math.pow(1 - phase, 3);
  const k = Math.min(1, phase / 0.12);
  const fadeIn = k * k * (3 - 2 * k);
  const a = fadeIn * Math.pow(1 - phase, 1.6);
  return { r: RING_R0 + (RING_R - RING_R0) * grow, a: a < 1e-4 ? 0 : a };
}

export type Rgb = readonly [number, number, number];

/** Parse #rgb, #rrggbb or rgb()/rgba() (as a canvas normalises colours) into 0-255 channels. */
export function parseColor(c: string): Rgb | null {
  const v = parseRgba(c);
  return v ? [v[0], v[1], v[2]] : null;
}

export type Rgba = readonly [number, number, number, number];

/** Like parseColor, but keeps the alpha (0..1; 1 when the colour has none). */
export function parseRgba(c: string): Rgba | null {
  const s = c.trim();
  let m = /^#([0-9a-f]{3})$/i.exec(s);
  if (m) {
    const h = m[1];
    return [parseInt(h[0] + h[0], 16), parseInt(h[1] + h[1], 16), parseInt(h[2] + h[2], 16), 1];
  }
  m = /^#([0-9a-f]{6})([0-9a-f]{2})?$/i.exec(s);
  if (m) {
    const h = m[1];
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16), m[2] ? parseInt(m[2], 16) / 255 : 1];
  }
  m = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)(?:\s*[,/]\s*([\d.]+)(%?))?/i.exec(s);
  if (m) {
    const a = m[4] === undefined ? 1 : Number(m[4]) / (m[5] ? 100 : 1);
    return [Number(m[1]), Number(m[2]), Number(m[3]), Math.min(1, Math.max(0, a))];
  }
  return null;
}

/** Blend `from` toward `to` by `k` (0..1), as an rgb() string. */
export function mixColor(from: Rgb, to: Rgb, k: number): string {
  const t = Math.min(1, Math.max(0, k));
  const ch = (i: number) => Math.round(from[i] + (to[i] - from[i]) * t);
  return `rgb(${ch(0)}, ${ch(1)}, ${ch(2)})`;
}

export interface Tick {
  x: number;
  y: number;
}

export interface Spot {
  cx: number;
  cy: number;
  r: number;
  /** Half the height of the column's exploited stack: the ring is measured from here. */
  half: number;
}

/**
 * One halo per column: centred on the column's stack of exploited ticks and reaching `radius`
 * past its ends, so a taller stack gets a taller halo. Sorted left to right. CSS px.
 */
export function haloSpots(ticks: readonly Tick[], barW: number, segH: number, radius = HALO_R): Spot[] {
  const cols = new Map<number, { top: number; bottom: number }>();
  for (const t of ticks) {
    const c = cols.get(t.x);
    if (c) {
      c.top = Math.min(c.top, t.y);
      c.bottom = Math.max(c.bottom, t.y + segH);
    } else cols.set(t.x, { top: t.y, bottom: t.y + segH });
  }
  return [...cols.entries()]
    .map(([x, c]) => ({ cx: x + barW / 2, cy: (c.top + c.bottom) / 2, r: radius + (c.bottom - c.top) / 2, half: (c.bottom - c.top) / 2 }))
    .sort((a, b) => a.cx - b.cx);
}

/**
 * The rings for a set of halo spots: columns whose centres are closer than `gap` share one ring
 * around the group, so neighbouring new columns send out a single ring instead of several that
 * cross each other. The group's `half` reaches the far end of every stack in it. Sorted left to
 * right; `r` is kept from the widest member.
 */
export function ringSpots(spots: readonly Spot[], gap = RING_R): Spot[] {
  const sorted = [...spots].sort((a, b) => a.cx - b.cx);
  const groups: Spot[][] = [];
  for (const s of sorted) {
    const g = groups[groups.length - 1];
    const last = g?.[g.length - 1];
    if (last && Math.hypot(s.cx - last.cx, s.cy - last.cy) < gap) g.push(s);
    else groups.push([s]);
  }
  return groups.map((g) => {
    if (g.length === 1) return g[0];
    const cx = (Math.min(...g.map((s) => s.cx)) + Math.max(...g.map((s) => s.cx))) / 2;
    const cy = (Math.min(...g.map((s) => s.cy - s.half)) + Math.max(...g.map((s) => s.cy + s.half))) / 2;
    const half = Math.max(...g.map((s) => Math.hypot(s.cx - cx, s.cy - cy) + s.half));
    return { cx, cy, half, r: Math.max(...g.map((s) => s.r)) };
  });
}

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/**
 * The rects to repaint for a set of exploited ticks: one per column (a column's exploited ticks
 * are stacked together at its top), padded for the halo and the ring, snapped outward to whole device pixels
 * and clamped to the canvas. All values are in CSS px.
 */
export function pulseRegions(ticks: readonly Tick[], barW: number, segH: number, width: number, height: number, dpr = 1, pad = PULSE_PAD): Rect[] {
  const cols = new Map<number, { x: number; top: number; bottom: number }>();
  for (const t of ticks) {
    const c = cols.get(t.x);
    if (c) {
      c.top = Math.min(c.top, t.y);
      c.bottom = Math.max(c.bottom, t.y + segH);
    } else cols.set(t.x, { x: t.x, top: t.y, bottom: t.y + segH });
  }
  const out: Rect[] = [];
  const snapDown = (v: number) => Math.floor(v * dpr) / dpr;
  const snapUp = (v: number) => Math.ceil(v * dpr) / dpr;
  for (const c of cols.values()) {
    // The halo and the ring are round and grow with the stack, so a tall stack needs as much room
    // to the sides as above and below.
    const side = pad + (c.bottom - c.top) / 2;
    const x0 = Math.max(0, snapDown(c.x - side));
    const y0 = Math.max(0, snapDown(c.top - pad));
    const x1 = Math.min(width, snapUp(c.x + barW + side));
    const y1 = Math.min(height, snapUp(c.bottom + pad));
    if (x1 > x0 && y1 > y0) out.push({ x: x0, y: y0, w: x1 - x0, h: y1 - y0 });
  }
  return out.sort((a, b) => a.x - b.x);
}

/**
 * The rects to repaint for a set of rings at their widest (see ringSpots), snapped outward to whole
 * device pixels and clamped to the canvas. CSS px.
 */
export function ringRegions(rings: readonly Spot[], width: number, height: number, dpr = 1, reach = RING_R + RING_W / 2 + 1): Rect[] {
  const snapDown = (v: number) => Math.floor(v * dpr) / dpr;
  const snapUp = (v: number) => Math.ceil(v * dpr) / dpr;
  const out: Rect[] = [];
  for (const s of rings) {
    const R = s.half + reach;
    const x0 = Math.max(0, snapDown(s.cx - R));
    const y0 = Math.max(0, snapDown(s.cy - R));
    const x1 = Math.min(width, snapUp(s.cx + R));
    const y1 = Math.min(height, snapUp(s.cy + R));
    if (x1 > x0 && y1 > y0) out.push({ x: x0, y: y0, w: x1 - x0, h: y1 - y0 });
  }
  return out.sort((a, b) => a.x - b.x);
}

/**
 * Rects that overlap or touch are replaced by their bounding rect until none do, so each pixel is
 * repainted once a frame. Sorted left to right.
 */
export function mergeRects(rects: readonly Rect[]): Rect[] {
  let out = rects.map((r) => ({ ...r }));
  for (let merged = true; merged; ) {
    merged = false;
    const next: Rect[] = [];
    for (const r of out) {
      const o = next.find((n) => r.x <= n.x + n.w && n.x <= r.x + r.w && r.y <= n.y + n.h && n.y <= r.y + r.h);
      if (o) {
        const x1 = Math.max(o.x + o.w, r.x + r.w);
        const y1 = Math.max(o.y + o.h, r.y + r.h);
        o.x = Math.min(o.x, r.x);
        o.y = Math.min(o.y, r.y);
        o.w = x1 - o.x;
        o.h = y1 - o.y;
        merged = true;
      } else next.push(r);
    }
    out = next;
  }
  return out.sort((a, b) => a.x - b.x);
}

/**
 * Newly exploited CVEs per column: the per-hour counts summed over each column's hours (columns
 * are consecutive, `hours` long, from hour 0), capped at the column's exploited count `c[0]`.
 * Empty when `fresh` is empty, so nothing pulses.
 */
export function freshPerBin(fresh: readonly number[], bins: readonly { hours: number; c: readonly number[] }[]): number[] {
  if (fresh.length === 0) return [];
  let h = 0;
  return bins.map((b) => {
    let n = 0;
    for (const end = h + b.hours; h < end; h++) n += fresh[h] ?? 0;
    return Math.min(n, b.c[0]);
  });
}

/**
 * How many of a column's `segs` exploited ticks stand for its `fresh` newly exploited CVEs out of
 * `exploited`: in proportion, at least one when any is new, and all of them only when all are new.
 * A single exploited tick pulses when any of its CVEs is new.
 */
export function freshSegs(segs: number, exploited: number, fresh: number): number {
  if (segs <= 0 || exploited <= 0 || fresh <= 0) return 0;
  if (fresh >= exploited) return segs;
  return Math.max(1, Math.min(segs - 1, Math.round((segs * fresh) / exploited)));
}

/**
 * The legend entry for newly exploited CVEs, number first: "3 newly exploited". It is always
 * shown, 0 included, so the legend keeps its size when the data arrives; null (still loading)
 * reads "… newly exploited".
 */
export function newLegend(count: number | null): string {
  return `${count === null ? '…' : fmtInt(count)} newly exploited`;
}
