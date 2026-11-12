import { WATCH_FLOOR, type Tier } from '../../../shared/contract';
import { useCountUp } from '../hooks';
import { TIER_META } from '../tiers';

const SWEEP = 270;

function polar(c: number, r: number, deg: number): [number, number] {
  const a = (deg * Math.PI) / 180;
  return [c + r * Math.sin(a), c - r * Math.cos(a)];
}

/** 0–100 gauge in the knob's geometry, with ticks for the watch floor and the current evidence bar. */
export function ScoreDial({ score, tier, knob, size = 168 }: { score: number; tier: Tier; knob: number; size?: number }) {
  const shown = useCountUp(score);
  const c = size / 2;
  const r = c - 12;
  const len = (Math.PI * 2 * r * SWEEP) / 360;
  const at = (v: number) => -SWEEP / 2 + (SWEEP * v) / 100;
  const [x0, y0] = polar(c, r, -SWEEP / 2);
  const [x1, y1] = polar(c, r, SWEEP / 2);
  const track = `M${x0} ${y0}A${r} ${r} 0 1 1 ${x1} ${y1}`;
  const tick = (v: number, cls: string, label: string) => {
    const [a0, b0] = polar(c, r - 9, at(v));
    const [a1, b1] = polar(c, r + 9, at(v));
    const [lx, ly] = polar(c, r + 18, at(v));
    return (
      <g class={cls}>
        <line x1={a0} y1={b0} x2={a1} y2={b1} />
        <text x={lx} y={ly} text-anchor="middle" dominant-baseline="middle">
          {label}
        </text>
      </g>
    );
  };
  return (
    <div class={`dial dial--${tier}`} style={{ width: `${size}px`, height: `${size}px` }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Score ${score} of 100, tier ${TIER_META[tier].label}. Evidence bar at ${knob}, watch floor ${WATCH_FLOOR}.`}>
        <path class="dial__track" d={track} />
        <path class="dial__fill" d={track} style={{ strokeDasharray: `${len}`, strokeDashoffset: `${len * (1 - Math.max(0, Math.min(100, shown)) / 100)}` }} />
        {tick(WATCH_FLOOR, 'dial__tick dial__tick--floor', String(WATCH_FLOOR))}
        {tick(knob, 'dial__tick dial__tick--knob', String(knob))}
      </svg>
      <div class="dial__center" aria-hidden="true">
        <span class="dial__num">{shown}</span>
        <span class="dial__of">/ 100</span>
      </div>
    </div>
  );
}
