/**
 * The exploited-tick pulse on the signal waterfall: the red ticks slowly brighten toward a hotter
 * red and back, all in phase, like one calm heartbeat. Pure helpers live here so they can be tested
 * without a canvas; Waterfall.tsx owns the timer and the drawing.
 */

/** One full breath (trough to peak and back), in ms. */
export const PULSE_PERIOD_MS = 2800;
/** Time between pulse frames: about 20 fps, which is plenty for a change this slow. */
export const PULSE_FRAME_MS = 50;
/** Glow radius at the peak, in CSS px. The static chart already has a 7px glow under it. */
export const PULSE_GLOW = 9;
/** Glow opacity at the peak. */
export const PULSE_GLOW_ALPHA = 0.55;
/** Room kept around each tick for its glow, so a repaint never cuts a glow off mid-fade. */
export const PULSE_PAD = PULSE_GLOW + 4;

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
  const s = c.trim();
  let m = /^#([0-9a-f]{3})$/i.exec(s);
  if (m) return [0, 1, 2].map((i) => parseInt(m![1][i] + m![1][i], 16)) as unknown as Rgb;
  m = /^#([0-9a-f]{6})([0-9a-f]{2})?$/i.exec(s);
  if (m) return [0, 2, 4].map((i) => parseInt(m![1].slice(i, i + 2), 16)) as unknown as Rgb;
  m = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(s);
  if (m) return [Number(m[1]), Number(m[2]), Number(m[3])];
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

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/**
 * The rects to repaint for a set of exploited ticks: one per column (a column's exploited ticks
 * are stacked together at its top), padded for the glow, snapped outward to whole device pixels
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
