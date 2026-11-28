/**
 * CVEs per month over the last three years as a line with a soft fill, the months of `lit` marked
 * with dots. It draws itself in once (CSS), in pixels so the dots stay round at any width.
 */
import { useWidth } from '../hooks';

export const SPARK_MONTHS = 36;

export function Spark({ monthly, lit, height = 72 }: { monthly: readonly { month: string; published: number }[]; lit: { start: string; end: string } | null; height?: number }) {
  const [ref, W] = useWidth<HTMLDivElement>();
  const rows = monthly.slice(-SPARK_MONTHS);
  const H = height;
  const max = Math.max(1, ...rows.map((r) => r.published));
  const x = (i: number) => 4 + (rows.length > 1 ? (i * (W - 8)) / (rows.length - 1) : (W - 8) / 2);
  const y = (v: number) => H - 3 - (v / max) * (H - 10);
  const line = rows.map((r, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(r.published).toFixed(1)}`).join('');
  const dots = lit ? rows.map((r, i) => ({ r, i })).filter(({ r }) => r.month >= lit.start && r.month <= lit.end) : [];
  return (
    <div class="spark" ref={ref} style={{ height: `${H}px` }} aria-hidden="true">
      {W > 0 && rows.length > 1 && (
        <svg width={W} height={H} focusable="false">
          <defs>
            <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stop-color="currentColor" stop-opacity="0.3" />
              <stop offset="1" stop-color="currentColor" stop-opacity="0" />
            </linearGradient>
          </defs>
          <path class="spark__area" d={`${line}L${x(rows.length - 1)} ${H}L${x(0)} ${H}Z`} fill="url(#spark-fill)" />
          <path class="spark__line" d={line} pathLength={1} />
          {dots.map(({ r, i }) => (
            <circle key={r.month} class="spark__dot" cx={x(i)} cy={y(r.published)} r={3.5} />
          ))}
        </svg>
      )}
    </div>
  );
}
