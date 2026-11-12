/**
 * Rotary threshold control. role="slider": arrows ±5 (Shift ±1), PageUp/PageDown ±10, Home/End.
 * Drag up/right to raise, down/left to lower; values snap magnetically to the 5-point detents.
 * Double-click returns to the default.
 */
import { useRef, useState } from 'preact/hooks';

interface KnobProps {
  value: number;
  min: number;
  max: number;
  defaultValue: number;
  onChange: (value: number) => void;
  label: string;
  valueText: string;
  size?: number;
  /** Values that get a long tick (the presets). */
  marks?: readonly number[];
}

const SWEEP = 270;
const DETENT = 5;

function polar(c: number, r: number, deg: number): [number, number] {
  const a = (deg * Math.PI) / 180;
  return [c + r * Math.sin(a), c - r * Math.cos(a)];
}

function arc(c: number, r: number, from: number, to: number): string {
  const [x0, y0] = polar(c, r, from);
  const [x1, y1] = polar(c, r, to);
  return `M${x0.toFixed(2)} ${y0.toFixed(2)}A${r} ${r} 0 ${to - from > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

export function Knob({ value, min, max, defaultValue, onChange, label, valueText, size = 136, marks = [] }: KnobProps) {
  const [dragging, setDragging] = useState(false);
  const [pulse, setPulse] = useState(0);
  const drag = useRef<{ x: number; y: number; start: number; pointer: string } | null>(null);
  const last = useRef(value);

  const clamp = (v: number) => Math.min(max, Math.max(min, v));
  const angleOf = (v: number) => -SWEEP / 2 + (SWEEP * (v - min)) / (max - min);
  const commit = (v: number, pointer?: string) => {
    const next = clamp(Math.round(v));
    if (next === last.current) return;
    if (next % DETENT === 0) {
      setPulse((n) => n + 1);
      if (pointer === 'touch') navigator.vibrate?.(4);
    }
    last.current = next;
    onChange(next);
  };
  last.current = value;

  const onKeyDown = (e: KeyboardEvent) => {
    const step = e.shiftKey ? 1 : DETENT;
    const keys: Record<string, number> = {
      ArrowUp: value + step,
      ArrowRight: value + step,
      ArrowDown: value - step,
      ArrowLeft: value - step,
      PageUp: value + 10,
      PageDown: value - 10,
      Home: min,
      End: max,
    };
    if (!(e.key in keys)) return;
    e.preventDefault();
    e.stopPropagation();
    // Arrow presses land on detents even from an off-detent value.
    const target = keys[e.key];
    commit(step === DETENT && e.key.startsWith('Arrow') ? Math.round(target / DETENT) * DETENT : target);
  };

  const onPointerDown = (e: PointerEvent) => {
    if (e.button !== 0) return;
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
    drag.current = { x: e.clientX, y: e.clientY, start: value, pointer: e.pointerType };
    setDragging(true);
  };
  const onPointerMove = (e: PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const raw = d.start + (e.clientX - d.x - (e.clientY - d.y)) / 3;
    const detent = Math.round(raw / DETENT) * DETENT;
    commit(Math.abs(raw - detent) < 1.25 ? detent : raw, d.pointer);
  };
  const end = () => {
    drag.current = null;
    setDragging(false);
  };
  // On phones a vertical swipe scrolls the page (touch-action: pan-y) and the browser cancels the
  // drag: undo any turn from the first few pixels, so a scroll never moves the setting.
  const cancel = () => {
    const d = drag.current;
    end();
    if (d) commit(d.start);
  };

  const c = size / 2;
  const rTrack = c - 12;
  const rBody = rTrack - 11;
  const a = angleOf(value);
  const [ix0, iy0] = polar(c, rBody * 0.64, a);
  const [ix1, iy1] = polar(c, rBody * 0.9, a);
  const ticks: number[] = [];
  for (let v = min; v <= max; v += DETENT) ticks.push(v);

  return (
    <div
      class={`knob${dragging ? ' is-dragging' : ''}`}
      style={{ width: `${size}px`, height: `${size}px` }}
      role="slider"
      tabIndex={0}
      aria-label={label}
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={value}
      aria-valuetext={valueText}
      aria-orientation="vertical"
      onKeyDown={onKeyDown}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={end}
      onPointerCancel={cancel}
      onDblClick={() => commit(defaultValue)}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true" focusable="false">
        <defs>
          <radialGradient id="knob-body" cx="50%" cy="32%" r="75%">
            <stop offset="0%" stop-color="var(--knob-hi)" />
            <stop offset="100%" stop-color="var(--knob-lo)" />
          </radialGradient>
        </defs>
        {ticks.map((v) => {
          const major = marks.includes(v) || v === min || v === max;
          const [x0, y0] = polar(c, rTrack + 5, angleOf(v));
          const [x1, y1] = polar(c, rTrack + (major ? 10 : 8), angleOf(v));
          return <line key={v} class={`knob__tick${v <= value ? ' is-on' : ''}${major ? ' is-major' : ''}`} x1={x0} y1={y0} x2={x1} y2={y1} />;
        })}
        <path class="knob__track" d={arc(c, rTrack, -SWEEP / 2, SWEEP / 2)} />
        {value > min && <path class="knob__value" d={arc(c, rTrack, -SWEEP / 2, a)} />}
        <circle class="knob__body" cx={c} cy={c} r={rBody} fill="url(#knob-body)" />
        <circle class="knob__rim" cx={c} cy={c} r={rBody - 3} />
        <line key={pulse} class={`knob__needle${pulse ? ' is-detent' : ''}`} x1={ix0} y1={iy0} x2={ix1} y2={iy1} />
      </svg>
      <span class="knob__value-text" style={{ fontSize: `${Math.round(size * 0.19)}px` }} aria-hidden="true">
        {value}
      </span>
    </div>
  );
}
