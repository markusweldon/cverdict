/**
 * The signal waterfall: one column per time bin across the window, stacked LED-style ticks.
 * Noise (watch, quiet) stays dim; passed CVEs (exploited, likely) glow in their tier colour.
 * Height ∝ √count so a 1,400-CVE patch day does not flatten everything else.
 */
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { Tier } from '../../../shared/contract';
import type { HourCounts } from '../filters';
import { fmtDate, fmtHour, fmtInt, HOUR_MS, DAY_MS } from '../format';
import { prefersReducedMotion } from '../hooks';
import { theme, useStore } from '../state';
import { TIER_META } from '../tiers';

export interface Annotation {
  at: number;
  label: string;
}

interface Props {
  counts: readonly HourCounts[];
  /** Start of the first hourly bucket (ms). */
  start: number;
  annotations?: readonly Annotation[];
  height?: number;
  summary: string;
}

const PITCH = 3;
const SEG = 2;
const TOP = 18;
const AXIS = 20;
const ORDER: readonly Tier[] = ['exploited', 'likely', 'watch', 'quiet'];

interface Bin {
  from: number;
  hours: number;
  c: HourCounts;
}

function readColors(el: Element) {
  const s = getComputedStyle(el);
  const v = (name: string) => s.getPropertyValue(name).trim();
  return {
    exploited: v('--exploited'),
    likely: v('--likely'),
    watch: v('--wf-watch'),
    quiet: v('--wf-quiet'),
    hover: v('--wf-hover'),
    axis: v('--border'),
    label: v('--muted'),
    cross: v('--faint-ui'),
    mono: v('--font-mono') || 'monospace',
  };
}

export function Waterfall({ counts, start, annotations = [], height = 176, summary }: Props) {
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [width, setWidth] = useState(0);
  const [hover, setHover] = useState<number | null>(null);
  const [progress, setProgress] = useState(() => (prefersReducedMotion() ? 1 : 0));
  const mode = useStore(theme);

  useEffect(() => {
    const el = wrap.current!;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const hasData = counts.length > 0;
  useEffect(() => {
    if (!hasData || progress >= 1) return;
    const t0 = performance.now();
    let raf = 0;
    const step = (t: number) => {
      const k = Math.min(1, (t - t0) / 700);
      setProgress(1 - Math.pow(1 - k, 3));
      if (k < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
    // Intro runs once, when data first arrives.
  }, [hasData]);

  const bins = useMemo<Bin[]>(() => {
    if (width === 0 || counts.length === 0) return [];
    const per = Math.max(1, Math.ceil((counts.length * PITCH) / width));
    const out: Bin[] = [];
    for (let i = 0; i < counts.length; i += per) {
      const c: HourCounts = [0, 0, 0, 0];
      for (let j = i; j < Math.min(counts.length, i + per); j++) for (let k = 0; k < 4; k++) c[k] += counts[j][k];
      out.push({ from: start + i * HOUR_MS, hours: Math.min(per, counts.length - i), c });
    }
    return out;
  }, [counts, start, width]);

  useEffect(() => {
    const cv = canvas.current;
    if (!cv || width === 0) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    cv.width = Math.round(width * dpr);
    cv.height = Math.round(height * dpr);
    const ctx = cv.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    const col = readColors(cv);
    const plotH = height - TOP - AXIS;
    const base = TOP + plotH;
    const colW = bins.length > 0 ? width / bins.length : width;
    const barW = Math.max(1, colW - (colW >= 3 ? 1 : 0.5));
    const max = Math.max(1, ...bins.map((b) => b.c[0] + b.c[1] + b.c[2] + b.c[3]));

    // baseline and day ticks
    ctx.fillStyle = col.axis;
    ctx.fillRect(0, base + 1, width, 1);
    ctx.font = `10px ${col.mono}`;
    ctx.textBaseline = 'top';
    const end = start + counts.length * HOUR_MS;
    const firstDay = Math.ceil(start / DAY_MS) * DAY_MS;
    const xOf = (t: number) => ((t - start) / (end - start)) * width;
    let lastLabelEnd = -Infinity;
    for (let t = firstDay; t < end; t += DAY_MS) {
      const x = Math.round(xOf(t)) + 0.5;
      const monday = new Date(t).getUTCDay() === 1;
      ctx.fillStyle = col.axis;
      ctx.fillRect(x - 0.5, base + 2, 1, monday ? 5 : 3);
      if (monday) {
        const text = fmtDate(new Date(t).toISOString());
        const w = ctx.measureText(text).width;
        const lx = Math.min(width - w, Math.max(0, x - w / 2));
        if (lx > lastLabelEnd + 8) {
          ctx.fillStyle = col.label;
          ctx.fillText(text, lx, base + 8);
          lastLabelEnd = lx + w;
        }
      }
    }

    // columns
    const lit: { x: number; y: number; tier: Tier }[] = [];
    bins.forEach((b, i) => {
      const total = b.c[0] + b.c[1] + b.c[2] + b.c[3];
      if (total === 0) return;
      const x = i * colW;
      if (hover === i) {
        ctx.fillStyle = col.hover;
        ctx.fillRect(x - 1, TOP - 4, barW + 2, plotH + 4);
      }
      const segs = Math.max(1, Math.round((plotH * Math.sqrt(total / max)) / PITCH));
      const e = b.c[0] > 0 ? Math.max(1, Math.round((segs * b.c[0]) / total)) : 0;
      const l = b.c[1] > 0 ? Math.max(1, Math.round((segs * b.c[1]) / total)) : 0;
      const rest = Math.max(0, segs - e - l);
      const noise = b.c[2] + b.c[3];
      const w = b.c[2] > 0 && rest > 0 ? Math.max(1, Math.round((rest * b.c[2]) / Math.max(1, noise))) : 0;
      const q = Math.max(0, rest - w);
      const stack: [Tier, number][] = [['quiet', q], ['watch', w], ['likely', l], ['exploited', e]];
      const visible = Math.ceil((q + w + l + e) * progress);
      let n = 0;
      for (const [tier, count] of stack) {
        for (let s = 0; s < count && n < visible; s++, n++) {
          const y = base - (n + 1) * PITCH + (PITCH - SEG);
          if (tier === 'exploited' || tier === 'likely') lit.push({ x, y, tier });
          else {
            ctx.fillStyle = tier === 'watch' ? col.watch : col.quiet;
            ctx.fillRect(x, y, barW, SEG);
          }
        }
      }
    });
    // passed ticks last, with glow, so neighbouring noise never covers them
    ctx.shadowBlur = 7;
    for (const t of lit) {
      const c = t.tier === 'exploited' ? col.exploited : col.likely;
      ctx.shadowColor = c;
      ctx.fillStyle = c;
      ctx.fillRect(t.x, t.y, barW, SEG);
    }
    ctx.shadowBlur = 0;

    // annotations: biggest first (callers pass them in that order); skip any that would collide
    ctx.textBaseline = 'alphabetic';
    const placed: [number, number][] = [];
    for (const a of annotations) {
      const i = Math.floor((a.at - start) / HOUR_MS / Math.max(1, bins[0]?.hours ?? 1));
      if (i < 0 || i >= bins.length) continue;
      const x = i * colW + barW / 2;
      const w = ctx.measureText(a.label).width;
      const lx = Math.min(width - w, Math.max(0, x - w / 2));
      if (placed.some(([l, r]) => lx < r + 10 && lx + w > l - 10)) continue;
      ctx.fillStyle = col.label;
      ctx.fillText(a.label, lx, TOP - 6);
      placed.push([lx, lx + w]);
    }

    if (hover !== null && bins[hover]) {
      ctx.fillStyle = col.cross;
      ctx.fillRect(Math.round(hover * colW + barW / 2), TOP - 2, 1, plotH + 2);
    }
  }, [bins, width, height, hover, progress, mode, annotations, counts.length, start]);

  const binAt = (clientX: number) => {
    const r = canvas.current!.getBoundingClientRect();
    if (bins.length === 0) return null;
    return Math.min(bins.length - 1, Math.max(0, Math.floor(((clientX - r.left) / r.width) * bins.length)));
  };
  const onKey = (e: KeyboardEvent) => {
    if (bins.length === 0) return;
    const step = e.shiftKey ? 12 : 1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      e.stopPropagation();
      setHover((h) => Math.min(bins.length - 1, Math.max(0, (h ?? bins.length - 1) + (e.key === 'ArrowRight' ? step : -step))));
    } else if (e.key === 'Escape') setHover(null);
  };

  const hb = hover !== null ? bins[hover] : undefined;
  const describe = (b: Bin) => {
    const range = `${fmtDate(new Date(b.from).toISOString())} · ${fmtHour(b.from)}–${fmtHour(b.from + b.hours * HOUR_MS)} UTC`;
    return { range, text: `${range}: ${ORDER.map((t, k) => `${fmtInt(b.c[k])} ${TIER_META[t].label.toLowerCase()}`).join(', ')}` };
  };
  const tipLeft = hover !== null && bins.length > 0 ? ((hover + 0.5) / bins.length) * width : 0;

  return (
    <div class="wf" ref={wrap}>
      <canvas
        ref={canvas}
        class="wf__canvas"
        style={{ height: `${height}px` }}
        tabIndex={0}
        role="img"
        aria-label={`${summary} Use the left and right arrow keys to read individual time bins.`}
        onPointerMove={(e) => setHover(binAt(e.clientX))}
        onPointerLeave={() => setHover(null)}
        onKeyDown={onKey}
        onBlur={() => setHover(null)}
      />
      {hb && (
        <div class={`wf__tip${tipLeft > width - 200 ? ' is-left' : ''}`} style={{ left: `${tipLeft}px` }} aria-hidden="true">
          <div class="wf__tip-head">{describe(hb).range}</div>
          {ORDER.map((t, k) => (
            <div key={t} class="wf__tip-row">
              <span class={`wf__key wf__key--${t}`} />
              <span class="wf__tip-val">{fmtInt(hb.c[k])}</span>
              <span class="wf__tip-label">{TIER_META[t].label}</span>
            </div>
          ))}
        </div>
      )}
      <div class="sr-only" aria-live="polite">
        {hb ? describe(hb).text : ''}
      </div>
    </div>
  );
}
