/**
 * The signal waterfall: one column per time bin across the window, stacked LED-style ticks.
 * Noise (watch, quiet) stays dim; passed CVEs (exploited, likely) glow in their tier colour.
 * Height ∝ √count so a 1,400-CVE patch day does not flatten everything else.
 *
 * With `dayHref`, a column opens Explore for the UTC day it starts on: a mouse click or Enter
 * goes straight there; on touch the first tap selects the column and only the tooltip's link
 * navigates, so scrolling past the chart never does.
 */
import { Fragment } from 'preact';
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { Tier } from '../../../shared/contract';
import { binDay, binRange, binsOf, dayStart, dayTotal, hoursPerBin, placeLabels, type Bin } from '../drill';
import type { HourCounts } from '../filters';
import { fmtDate, fmtInt, HOUR_MS, DAY_MS, plural } from '../format';
import { prefersReducedMotion } from '../hooks';
import { navigate } from '../router';
import { theme, useStore } from '../state';
import { TIER_META } from '../tiers';
import { IconArrowRight } from './icons';

export interface AnnotationPart {
  text: string;
  /** In-app link, e.g. the batch card on /batches. */
  href?: string;
}

export interface Annotation {
  at: number;
  /** Shown joined by " + ": "Oracle 1,076 + Chrome 353". */
  parts: readonly AnnotationPart[];
}

interface Props {
  counts: readonly HourCounts[];
  /** Start of the first hourly bucket (ms). */
  start: number;
  annotations?: readonly Annotation[];
  height?: number;
  summary: string;
  /** Reports how many hours each column covers at the current width (for the caption). */
  onBinHours?: (hours: number) => void;
  /** Where a column's day opens (YYYY-MM-DD → in-app href). Without it the chart is read-only. */
  dayHref?: (day: string) => string;
}

const PITCH = 3;
const SEG = 2;
const TOP = 18;
const AXIS = 20;
const ORDER: readonly Tier[] = ['exploited', 'likely', 'watch', 'quiet'];
/** A press that travels further than this is a drag or a swipe, not a click. */
const SLOP = 8;

type Via = 'mouse' | 'key' | 'touch';

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

interface Placed {
  a: Annotation;
  left: number;
  /** Pinned to the right edge instead of `left`, so a label never widens the page. */
  right: boolean;
}

export function Waterfall({ counts, start, annotations = [], height = 176, summary, onBinHours, dayHref }: Props) {
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const tip = useRef<HTMLDivElement>(null);
  const down = useRef<{ x: number; y: number; type: string } | null>(null);
  const [width, setWidth] = useState(0);
  const [active, setActive] = useState<number | null>(null);
  const [via, setVia] = useState<Via>('mouse');
  const [progress, setProgress] = useState(() => (prefersReducedMotion() ? 1 : 0));
  const mode = useStore(theme);
  const interactive = dayHref !== undefined;

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

  const bins = useMemo<Bin<number[]>[]>(() => (width === 0 || counts.length === 0 ? [] : binsOf(counts, start, hoursPerBin(counts.length, width, PITCH))), [counts, start, width]);
  const per = bins[0]?.hours ?? 1;

  useEffect(() => {
    if (bins.length > 0) onBinHours?.(bins[0].hours);
  }, [bins[0]?.hours]);

  // A new width regroups the columns: the old index points at another time.
  useEffect(() => setActive(null), [per]);

  // Spike labels are links, so they are laid out here (with the canvas font) and rendered as HTML.
  const placed = useMemo<Placed[]>(() => {
    if (!wrap.current || bins.length === 0) return [];
    const ctx = document.createElement('canvas').getContext('2d');
    if (!ctx) return [];
    ctx.font = `10px ${getComputedStyle(wrap.current).getPropertyValue('--font-mono').trim() || 'monospace'}`;
    const colW = width / bins.length;
    const barW = Math.max(1, colW - (colW >= 3 ? 1 : 0.5));
    const labels: { item: Annotation; x: number; w: number }[] = [];
    // Biggest first (callers pass them in that order), so a collision drops the smaller one.
    for (const a of annotations) {
      const i = Math.floor((a.at - start) / HOUR_MS / per);
      if (i < 0 || i >= bins.length) continue;
      labels.push({ item: a, x: i * colW + barW / 2, w: Math.ceil(ctx.measureText(a.parts.map((p) => p.text).join(' + ')).width) });
    }
    return placeLabels(labels, width).map(({ item, left, right }) => ({ a: item, left, right }));
  }, [annotations, bins.length, per, width, start, mode]);

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
      if (active === i) {
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

    if (active !== null && bins[active]) {
      ctx.fillStyle = col.cross;
      ctx.fillRect(Math.round(active * colW + barW / 2), TOP - 2, 1, plotH + 2);
    }
  }, [bins, width, height, active, progress, mode, counts.length, start]);

  // A tapped column stays selected until the next tap elsewhere on the page.
  useEffect(() => {
    if (via !== 'touch' || active === null) return;
    const away = (e: PointerEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setActive(null);
    };
    document.addEventListener('pointerdown', away);
    return () => document.removeEventListener('pointerdown', away);
  }, [via, active]);

  const binAt = (clientX: number) => {
    const r = canvas.current!.getBoundingClientRect();
    if (bins.length === 0) return null;
    return Math.min(bins.length - 1, Math.max(0, Math.floor(((clientX - r.left) / r.width) * bins.length)));
  };
  const dayInfo = (b: Bin<number[]>) => {
    const day = binDay(b.from);
    // A non-breaking space keeps "Oct 4" together when the hint wraps.
    return { day, label: fmtDate(day).replace(' ', '\u00a0'), total: dayTotal(counts, start, dayStart(b.from)) };
  };
  const open = (i: number | null) => {
    const b = i === null ? undefined : bins[i];
    if (!b || !dayHref) return;
    const d = dayInfo(b);
    if (d.total > 0) navigate(dayHref(d.day));
  };
  const onKey = (e: KeyboardEvent) => {
    if (bins.length === 0) return;
    const last = bins.length - 1;
    const big = 12;
    const next = (h: number | null) => (h === null ? last : h + (e.shiftKey ? big : 1));
    const prev = (h: number | null) => (h === null ? last : h - (e.shiftKey ? big : 1));
    // Up and Down too: a slider answers to every arrow key, and screen reader users expect that.
    const moves: Record<string, (h: number | null) => number> = {
      ArrowRight: next,
      ArrowUp: next,
      ArrowLeft: prev,
      ArrowDown: prev,
      PageUp: (h) => (h ?? last) + big,
      PageDown: (h) => (h ?? last) - big,
      Home: () => 0,
      End: () => last,
    };
    const move = moves[e.key];
    if (move) {
      e.preventDefault();
      e.stopPropagation();
      setVia('key');
      setActive((h) => Math.min(last, Math.max(0, move(h))));
    } else if (e.key === 'Enter' && interactive && active !== null) {
      e.preventDefault();
      e.stopPropagation();
      open(active);
    } else if (e.key === 'Escape') setActive(null);
  };

  const hb = active !== null ? bins[active] : undefined;
  const describe = (b: Bin<number[]>) => {
    const range = binRange(b.from, b.hours);
    return { range, text: `${range}: ${ORDER.map((t, k) => `${fmtInt(b.c[k])} ${TIER_META[t].label.toLowerCase()}`).join(', ')}` };
  };
  const info = hb && interactive ? dayInfo(hb) : null;
  const tipX = active !== null && bins.length > 0 ? ((active + 0.5) / bins.length) * width : 0;

  // Keep the tooltip inside the chart: right of the column when it fits, else left of it, else
  // against whichever edge is nearer. Measured, because the hint and the link change its width.
  useLayoutEffect(() => {
    const el = tip.current;
    if (!el) return;
    const w = el.offsetWidth;
    const gap = 14;
    const left = tipX + gap + w <= width ? tipX + gap : tipX - gap - w >= 0 ? tipX - gap - w : Math.max(0, Math.min(width - w, tipX - w / 2));
    el.style.left = `${Math.round(left)}px`;
  });

  // Interactive, the canvas is a slider: one focusable control whose arrow keys pick a value (a
  // time slot) from an ordered range, which is exactly what this chart does. That role makes
  // screen readers switch to focus mode so the arrow keys reach it (role="img" would leave them
  // to the reader's own navigation), announces the picked slot through aria-valuetext, and Enter
  // acts on the current value. Alternatives: "img" cannot be operated, "listbox"/"grid" need one
  // DOM element per column (up to 360 of them), "application" removes every reader convention.
  const sliderProps = interactive
    ? {
        role: 'slider' as const,
        'aria-label': 'Signal waterfall',
        'aria-describedby': 'wf-desc',
        'aria-valuemin': 1,
        'aria-valuemax': Math.max(1, bins.length),
        'aria-valuenow': (active ?? Math.max(0, bins.length - 1)) + 1,
        'aria-valuetext': hb ? `${describe(hb).text}.${info && info.total > 0 ? ` Press Enter to see the ${plural(info.total, 'CVE')} from ${info.label}.` : ''}` : 'No time slot picked. Use the arrow keys to pick one.',
      }
    : { role: 'img' as const, 'aria-label': `${summary} Use the left and right arrow keys to read individual time bins.` };

  return (
    <div class={`wf${interactive ? ' wf--drill' : ''}`} ref={wrap}>
      <canvas
        ref={canvas}
        class="wf__canvas"
        style={{ height: `${height}px` }}
        tabIndex={0}
        {...sliderProps}
        onPointerDown={(e) => {
          down.current = { x: e.clientX, y: e.clientY, type: e.pointerType };
        }}
        onPointerMove={(e) => {
          // Touch has no hover: a finger moving over the chart is scrolling the page.
          if (e.pointerType === 'touch') return;
          setVia('mouse');
          setActive(binAt(e.clientX));
        }}
        onPointerLeave={(e) => {
          if (e.pointerType !== 'touch' && via === 'mouse') setActive(null);
        }}
        onClick={(e) => {
          const d = down.current;
          down.current = null;
          if (!interactive || !d || Math.hypot(e.clientX - d.x, e.clientY - d.y) > SLOP) return;
          const i = binAt(e.clientX);
          if (d.type === 'touch') {
            setVia('touch');
            setActive(i);
          } else open(i);
        }}
        onKeyDown={onKey}
        onBlur={() => {
          // A tapped column keeps its tooltip (its link takes focus when tapped).
          if (via !== 'touch') setActive(null);
        }}
      />
      {placed.map(({ a, left, right }) => (
        <span key={a.at} class="wf__note" style={right ? { right: '0px' } : { left: `${left}px` }}>
          {a.parts.map((p, k) => (
            <Fragment key={k}>
              {k > 0 && ' + '}
              {p.href ? (
                <a class="wf__note-link" href={p.href}>
                  {p.text}
                </a>
              ) : (
                p.text
              )}
            </Fragment>
          ))}
        </span>
      ))}
      {hb && (
        <div ref={tip} class={`wf__tip${via === 'touch' ? ' is-pinned' : ''}`}>
          <div aria-hidden="true">
            {/* A column that crosses midnight may wrap, but only between its two ends. */}
            <div class="wf__tip-head">
              {describe(hb)
                .range.split(' – ')
                .map((end) => end.replace(/ /g, '\u00a0'))
                .join(' – ')}
            </div>
            {ORDER.map((t, k) => (
              <div key={t} class="wf__tip-row">
                <span class={`wf__key wf__key--${t}`} />
                <span class="wf__tip-val">{fmtInt(hb.c[k])}</span>
                <span class="wf__tip-label">{TIER_META[t].label}</span>
              </div>
            ))}
            {info && info.total > 0 && via !== 'touch' && (
              <p class="wf__tip-hint">
                {via === 'key' ? 'Press Enter' : 'Click'} to see the {plural(info.total, 'CVE')} from {info.label}
              </p>
            )}
          </div>
          {info && info.total > 0 && via === 'touch' && dayHref && (
            <a class="wf__tip-go" href={dayHref(info.day)}>
              See {info.label} <IconArrowRight size={12} />
            </a>
          )}
        </div>
      )}
      {interactive && (
        <p class="sr-only" id="wf-desc">
          {summary} Use the arrow keys to move between time slots, and Enter to see that day’s CVEs in Explore.
        </p>
      )}
      {/* Keyboard moves are announced by the slider's aria-valuetext; this reads out pointer hover and taps. */}
      <div class="sr-only" aria-live="polite">
        {hb && (!interactive || via !== 'key') ? describe(hb).text : ''}
      </div>
    </div>
  );
}
