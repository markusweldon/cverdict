/**
 * The exploited-tick pulse on the signal waterfall. Only CVEs that became Exploited in the last
 * 72 hours (stats.json hourly.new_exploited) pulse: a soft red halo slowly swells behind their
 * ticks and fades again, while the ticks themselves shift toward a stronger red, all in
 * phase, like one calm breath. The ticks are only about 2x2 px, so the halo carries the visible
 * change. Pure helpers live here so they can be tested without a canvas; Waterfall.tsx owns the
 * timer and the drawing.
 */
import { fmtInt } from './format';

/** One full breath (trough to peak and back), in ms. */
export const PULSE_PERIOD_MS = 2800;
/** Time between pulse frames: about 20 fps, which is plenty for a change this slow. */
export const PULSE_FRAME_MS = 50;
/** Halo radius around a column's exploited ticks, in CSS px (so about 20px across for one tick). */
export const HALO_R = 9;
/** Room kept around each column for its halo, so a repaint never cuts a halo off mid-fade. */
export const PULSE_PAD = HALO_R + 2;

/**
 * Pulse level for a time since the pulse started: 0 at the trough (the static colour), 1 at the
 * peak, eased in and out by a sine. Starts and ends each period at 0.
 */
export function pulseLevel(elapsedMs: number, periodMs = PULSE_PERIOD_MS): number {
  if (!(periodMs > 0) || !Number.isFinite(elapsedMs)) return 0;
  const phase = (((elapsedMs % periodMs) + periodMs) % periodMs) / periodMs;
  const v = (1 - Math.cos(2 * Math.PI * phase)) / 2;
  // Snap the float residue at the trough so level 0 really means "draw nothing".
  return v < 1e-9 ? 0 : v;
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
    .map(([x, c]) => ({ cx: x + barW / 2, cy: (c.top + c.bottom) / 2, r: radius + (c.bottom - c.top) / 2 }))
    .sort((a, b) => a.cx - b.cx);
}

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/**
 * The rects to repaint for a set of exploited ticks: one per column (a column's exploited ticks
 * are stacked together at its top), padded for the halo, snapped outward to whole device pixels
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
    const x0 = Math.max(0, snapDown(c.x - pad));
    const y0 = Math.max(0, snapDown(c.top - pad));
    const x1 = Math.min(width, snapUp(c.x + barW + pad));
    const y1 = Math.min(height, snapUp(c.bottom + pad));
    if (x1 > x0 && y1 > y0) out.push({ x: x0, y: y0, w: x1 - x0, h: y1 - y0 });
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

/** The legend entry for newly exploited CVEs, e.g. "New in 72h: 3"; null (no entry) when none qualify. */
export function newLegend(fresh: readonly number[]): string | null {
  const n = fresh.reduce((a, b) => a + b, 0);
  return n > 0 ? `New in 72h: ${fmtInt(n)}` : null;
}
