/**
 * The Surge's last 30 days in one chart: every CVE published per day as soft grey bars (the noise),
 * the ones that cleared the evidence bar lit in the tier colours inside them, and CISA KEV additions
 * in a lane under the axis. One square-root axis, like the waterfall, so a 2,000-CVE day does not
 * flatten the few that matter. Hover, tap or the arrow keys read a day; a click or Enter opens it in
 * Explore.
 */
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { exploreDayHref } from '../drill';
import { dailyTotals, sqrtTicks, sqrtTop, type DayRow } from '../daily';
import { fmtCompact, fmtDate, fmtInt, fmtPct, plural } from '../format';
import { useWidth } from '../hooks';
import { navigate } from '../router';
import { IconArrowRight } from './icons';

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
/** A tap that moves further than this (px) is a scroll, not a pick. */
const SLOP = 8;
const PLOT_H = 210;
const KEV_LANE = 24;
const H = 12 + PLOT_H + KEV_LANE + 18;
const M = { l: 40, r: 8, t: 12 };

interface Props {
  days: readonly DayRow[];
  kev: ReadonlyMap<string, number>;
  /** KEV additions are known (kev.json loaded). Without it the lane and its rows stay out. */
  kevReady: boolean;
  /** The last day is still filling up. */
  partialLast: boolean;
  knob: number;
}

const weekday = (date: string) => WEEKDAYS[new Date(`${date}T00:00:00Z`).getUTCDay()];

/** A bar from the baseline up to `y`, its top corners rounded by up to `r`. */
function barPath(cx: number, bw: number, y: number, base: number, r: number): string {
  const rr = Math.min(r, bw / 2, Math.max(0, base - y));
  const l = cx - bw / 2;
  const rt = cx + bw / 2;
  return `M${l} ${base}V${y + rr}Q${l} ${y} ${l + rr} ${y}H${rt - rr}Q${rt} ${y} ${rt} ${y + rr}V${base}Z`;
}

export function DailyChart({ days, kev, kevReady, partialLast, knob }: Props) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const wrap = useRef<HTMLDivElement>(null);
  const tip = useRef<HTMLDivElement>(null);
  const down = useRef<{ x: number; y: number; type: string } | null>(null);
  const [active, setActive] = useState<number | null>(null);
  const [via, setVia] = useState<'mouse' | 'touch' | 'key'>('mouse');
  const n = days.length;
  const w = Math.max(0, width - M.l - M.r);
  const slot = n > 0 ? w / n : 0;
  const bw = Math.max(3, Math.min(30, slot * 0.68));
  const base = M.t + PLOT_H;
  const top = sqrtTop(Math.max(1, ...days.map((d) => d.published)));
  const y = (v: number) => base - Math.sqrt(Math.max(0, v) / top) * PLOT_H;
  const ticks = sqrtTicks(top, PLOT_H);
  const cx = (i: number) => M.l + i * slot + slot / 2;
  const totals = dailyTotals(days, kev);
  const narrow = slot < 16;

  // A tapped day stays picked until the next tap elsewhere on the page.
  useEffect(() => {
    if (via !== 'touch' || active === null) return;
    const away = (e: PointerEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setActive(null);
    };
    document.addEventListener('pointerdown', away);
    return () => document.removeEventListener('pointerdown', away);
  }, [via, active]);

  // Right of the day when it fits, else left of it, else against the nearer edge.
  useLayoutEffect(() => {
    const el = tip.current;
    if (!el || active === null) return;
    const tw = el.offsetWidth;
    const x = cx(active);
    const gap = 14;
    const left = x + gap + tw <= width ? x + gap : x - gap - tw >= 0 ? x - gap - tw : Math.max(0, Math.min(width - tw, x - tw / 2));
    el.style.left = `${Math.round(left)}px`;
  });

  const dayAt = (clientX: number, el: Element) => {
    const r = el.getBoundingClientRect();
    if (n === 0 || slot <= 0) return null;
    return Math.min(n - 1, Math.max(0, Math.floor((clientX - r.left - M.l) / slot)));
  };
  const open = (i: number | null) => {
    const d = i === null ? undefined : days[i];
    if (d && d.published > 0) navigate(exploreDayHref(d.date, knob));
  };
  const label = (i: number) => `${weekday(days[i].date)}, ${fmtDate(days[i].date)}${partialLast && i === n - 1 ? ' so far' : ''}`;
  const describe = (i: number) => {
    const d = days[i];
    const k = kevReady ? `, ${fmtInt(kev.get(d.date) ?? 0)} added to KEV` : '';
    return `${label(i)}: ${plural(d.published, 'CVE')}, ${fmtInt(d.passed)} cleared the bar, ${fmtInt(d.exploited)} exploited${k}`;
  };
  const onKey = (e: KeyboardEvent) => {
    if (n === 0) return;
    const last = n - 1;
    const moves: Record<string, (h: number | null) => number> = {
      ArrowRight: (h) => (h === null ? last : h + (e.shiftKey ? 7 : 1)),
      ArrowUp: (h) => (h === null ? last : h + 1),
      ArrowLeft: (h) => (h === null ? last : h - (e.shiftKey ? 7 : 1)),
      ArrowDown: (h) => (h === null ? last : h - 1),
      PageUp: (h) => (h ?? last) + 7,
      PageDown: (h) => (h ?? last) - 7,
      Home: () => 0,
      End: () => last,
    };
    const move = moves[e.key];
    if (move) {
      e.preventDefault();
      e.stopPropagation();
      setVia('key');
      setActive((h) => Math.min(last, Math.max(0, move(h))));
    } else if (e.key === 'Enter' && active !== null) {
      e.preventDefault();
      e.stopPropagation();
      open(active);
    } else if (e.key === 'Escape' && active !== null) {
      e.stopPropagation();
      setActive(null);
    }
  };

  const a = active !== null ? days[active] : null;
  const aKev = a ? (kev.get(a.date) ?? 0) : 0;
  const summary = `${plural(totals.published, 'CVE')} published in the last ${n} days; ${fmtInt(totals.passed)} cleared the evidence bar, ${fmtInt(totals.exploited)} of them exploited.`;

  return (
    <div class="dc" ref={wrap}>
      <div class="chart__bar">
        <ul class="legend legend--inline dc__legend">
          <li class="legend__item">
            <span class="wf__key" />
            All CVEs <span class="legend__num">{fmtInt(totals.published)}</span>
          </li>
          <li class="legend__item">
            <span class="wf__key wf__key--likely" />
            Cleared the bar <span class="legend__num">{fmtInt(totals.passed)}</span>
          </li>
          <li class="legend__item">
            <span class="wf__key wf__key--exploited" />
            Exploited <span class="legend__num">{fmtInt(totals.exploited)}</span>
          </li>
          {kevReady && (
            <li class="legend__item">
              <span class="dc__key-kev" />
              Added to KEV <span class="legend__num">{fmtInt(totals.kev)}</span>
            </li>
          )}
        </ul>
      </div>
      <div class="chart__plot dc__plot" ref={ref} style={{ height: `${H}px` }}>
        {width > 0 && (
          <svg
            width={width}
            height={H}
            class="dc__svg"
            tabIndex={0}
            role="slider"
            aria-label="CVEs per day, last 30 days"
            aria-describedby="dc-desc"
            aria-valuemin={1}
            aria-valuemax={Math.max(1, n)}
            aria-valuenow={(active ?? Math.max(0, n - 1)) + 1}
            aria-valuetext={active !== null ? `${describe(active)}.${days[active].published > 0 ? ' Press Enter to see them in Explore.' : ''}` : 'No day picked. Use the arrow keys to pick one.'}
            onPointerDown={(e) => {
              down.current = { x: e.clientX, y: e.clientY, type: e.pointerType };
              // A tap picks without focusing, so no keyboard focus ring shows; the tap away clears it.
              if (e.pointerType === 'touch') e.preventDefault();
            }}
            onPointerMove={(e) => {
              // Touch has no hover: a finger moving over the chart is scrolling the page.
              if (e.pointerType === 'touch') return;
              setVia('mouse');
              setActive(dayAt(e.clientX, e.currentTarget));
            }}
            onPointerLeave={(e) => {
              if (e.pointerType !== 'touch' && via === 'mouse') setActive(null);
            }}
            onClick={(e) => {
              const d = down.current;
              down.current = null;
              if (!d || Math.hypot(e.clientX - d.x, e.clientY - d.y) > SLOP) return;
              const i = dayAt(e.clientX, e.currentTarget);
              if (d.type === 'touch') {
                setVia('touch');
                setActive(i);
              } else open(i);
            }}
            onKeyDown={onKey}
            onBlur={() => {
              if (via !== 'touch') setActive(null);
            }}
          >
            {ticks.map((t) => (
              <g key={t} class="chart__grid">
                <line x1={M.l} x2={width - M.r} y1={y(t)} y2={y(t)} />
                <text x={M.l - 8} y={y(t)} text-anchor="end" dominant-baseline="middle">
                  {fmtCompact(t)}
                </text>
              </g>
            ))}
            {active !== null && <rect class="dc__band" x={M.l + active * slot} y={M.t - 6} width={slot} height={PLOT_H + KEV_LANE + 6} rx={3} />}
            {kevReady && (
              <text class="dc__lane" x={M.l - 8} y={base + KEV_LANE / 2 + 1} text-anchor="end" dominant-baseline="middle">
                KEV
              </text>
            )}
            {days.map((d, i) => {
              const x = cx(i);
              const partial = partialLast && i === n - 1;
              const k = kev.get(d.date) ?? 0;
              const monday = new Date(`${d.date}T00:00:00Z`).getUTCDay() === 1;
              const r = Math.min(3, bw / 3);
              return (
                <g key={d.date} class={`dc__day${active === i ? ' is-on' : ''}${active !== null && active !== i ? ' is-off' : ''}`}>
                  {d.published > 0 && <path class={`dc__vol${partial ? ' is-partial' : ''}`} d={barPath(x, bw, y(d.published), base, r)} />}
                  {d.passed > 0 && <path class="dc__pass" d={barPath(x, bw, y(d.passed), base, r)} />}
                  {d.exploited > 0 && <path class="dc__exp" d={barPath(x, bw, y(d.exploited), base, r)} />}
                  {kevReady &&
                    k > 0 &&
                    (narrow ? (
                      <circle class="dc__kev" cx={x} cy={base + KEV_LANE / 2} r={2.5} />
                    ) : (
                      <g class="dc__kev">
                        <rect x={x - Math.max(7, 3 + String(k).length * 3.2)} y={base + KEV_LANE / 2 - 6.5} width={Math.max(14, 6 + String(k).length * 6.4)} height={13} rx={6.5} />
                        <text x={x} y={base + KEV_LANE / 2 + 0.5} text-anchor="middle" dominant-baseline="middle">
                          {k}
                        </text>
                      </g>
                    ))}
                  {monday && (
                    <text class="chart__xlabel" x={x} y={H - 4} text-anchor="middle">
                      {fmtDate(d.date)}
                    </text>
                  )}
                </g>
              );
            })}
            <line class="dc__base" x1={M.l} x2={width - M.r} y1={base + 0.5} y2={base + 0.5} />
          </svg>
        )}
        {a && active !== null && (
          <div ref={tip} class={`wf__tip dc__tip${via === 'touch' ? ' is-pinned' : ''}`}>
            <div aria-hidden="true">
              <div class="wf__tip-head">{label(active)}</div>
              <div class="wf__tip-row">
                <span class="wf__key" />
                <span class="wf__tip-val">{fmtInt(a.published)}</span>
                <span class="wf__tip-label">All CVEs</span>
              </div>
              <div class="wf__tip-row">
                <span class="wf__key wf__key--likely" />
                <span class="wf__tip-val">{fmtInt(a.passed)}</span>
                <span class="wf__tip-label">
                  Cleared the bar
                  {a.published > 0 && a.passed > 0 ? <span class="dc__pct"> {fmtPct(a.passed / a.published)}</span> : null}
                </span>
              </div>
              <div class="wf__tip-row">
                <span class="wf__key wf__key--exploited" />
                <span class="wf__tip-val">{fmtInt(a.exploited)}</span>
                <span class="wf__tip-label">Exploited</span>
              </div>
              {kevReady && (
                <div class="wf__tip-row">
                  <span class="dc__key-kev" />
                  <span class="wf__tip-val">{fmtInt(aKev)}</span>
                  <span class="wf__tip-label">Added to KEV</span>
                </div>
              )}
              {a.published > 0 && via !== 'touch' && <p class="wf__tip-hint">{via === 'key' ? 'Press Enter' : 'Click'} to see them in Explore</p>}
            </div>
            {a.published > 0 && via === 'touch' && (
              <a class="wf__tip-go" href={exploreDayHref(a.date, knob)}>
                See {fmtDate(a.date)} <IconArrowRight size={12} />
              </a>
            )}
          </div>
        )}
      </div>
      <p class="sr-only" id="dc-desc">
        {summary} Use the arrow keys to move between days, and Enter to see that day’s CVEs in Explore.
      </p>
      {/* Keyboard moves are announced by aria-valuetext; this reads out pointer hover and taps. */}
      <div class="sr-only" aria-live="polite">
        {active !== null && via !== 'key' ? describe(active) : ''}
      </div>
    </div>
  );
}
