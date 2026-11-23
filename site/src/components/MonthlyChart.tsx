/**
 * CVEs per month on The Surge, with the controls an analyst expects: a date range (presets, month
 * inputs, drag to zoom), grouping, severity, CNA and KEV filters, a year-earlier comparison, log scale,
 * and CSV and PNG downloads. Every control lives in the URL (surgeview.ts). The tooltip, keys, summary
 * and table all read the same filtered series.
 */
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { SEVERITY_BANDS, type SeverityBand, type StatsFile, type SurgeFile } from '../../../shared/contract';
import { fmtChange } from '../daily';
import { downloadBlob, downloadPng } from '../exportchart';
import { fmtCompact, fmtInt, fmtMonth } from '../format';
import { useWidth } from '../hooks';
import { setQuery, useLocation } from '../router';
import { PACE_AXIS_HEADROOM, onPace } from '../surge';
import {
  BAND_LABELS,
  KERNEL_CNAS,
  PRESETS,
  WORDPRESS_CNAS,
  activeCnas,
  bucketLabel,
  busiestPoint,
  buildSeries,
  csvColumns,
  exportName,
  filterIndex,
  filterWords,
  pointChange,
  readView,
  toCsv,
  usableSurge,
  viewQuery,
  visibleOverlays,
  withPreset,
  xTicks,
  zoomTo,
  type Group,
  type Overlay,
  type Point,
  type View,
} from '../surgeview';

type Month = StatsFile['monthly'][number];

const LINE: Readonly<Record<Overlay, { label: string; cls: string }>> = {
  kevpub: { label: 'In CISA KEV (by publication)', cls: 's-kevpub' },
  kevadd: { label: 'Added to CISA KEV', cls: 's-kev' },
  ai: { label: 'AI-credited', cls: 's-ai' },
};
const GROUP_LABEL: Readonly<Record<Group, string>> = { month: 'Month', quarter: 'Quarter', year: 'Year' };
const GROUP_NOUN: Readonly<Record<Group, string>> = { month: 'month', quarter: 'quarter', year: 'year' };
/** Shift + arrow moves this many buckets: a year of months or quarters, five years. */
const BIG_STEP: Readonly<Record<Group, number>> = { month: 12, quarter: 4, year: 5 };

function niceStep(raw: number): number {
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(raw, 1e-9))));
  const f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
}

function scale(max: number, top: number, bottom: number, log: boolean) {
  if (log) {
    const hi = Math.ceil(Math.log10(Math.max(10, max)));
    const y = (v: number) => bottom - (Math.log10(Math.max(0, v) + 1) / hi) * (bottom - top);
    return { y, ticks: Array.from({ length: hi + 1 }, (_, i) => Math.pow(10, i)) };
  }
  const step = niceStep(Math.max(1, max) / 4);
  const hi = Math.ceil(Math.max(1, max) / step) * step;
  return { y: (v: number) => bottom - (v / hi) * (bottom - top), ticks: Array.from({ length: Math.round(hi / step) + 1 }, (_, i) => i * step) };
}

const PACE_DX = 6;
const H = 300;
const M = { l: 48, r: 14, t: 14, b: 26 };

function Toggle({ on, onClick, label, disabled, tip }: { on: boolean; onClick: () => void; label: string; disabled?: boolean; tip?: string }) {
  return (
    <button type="button" class="toggle" aria-pressed={on ? 'true' : 'false'} onClick={onClick} disabled={disabled} data-tip={tip}>
      <span class="toggle__box" aria-hidden="true" />
      {label}
    </button>
  );
}

function Seg<T extends string>({ label, value, options, onPick, disabled }: { label: string; value: T; options: readonly { id: T; label: string }[]; onPick: (v: T) => void; disabled?: boolean }) {
  return (
    <div class="seg seg--sm" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" class="seg__btn" aria-pressed={value === o.id ? 'true' : 'false'} disabled={disabled} onClick={() => onPick(o.id)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export interface MonthlyChartProps {
  monthly: readonly Month[];
  generatedAt: string;
  /** surge.json: the file, null while loading, or 'missing' when the data has none (older data). */
  surge: SurgeFile | null | 'missing';
}

export function MonthlyChart({ monthly, generatedAt, surge: surgeProp }: MonthlyChartProps) {
  const loc = useLocation();
  const view = useMemo(() => readView(loc.search), [loc.search]);
  const set = (next: View) => setQuery(viewQuery(next));
  const surgeFile = surgeProp === 'missing' ? null : surgeProp;
  const surge = useMemo(() => usableSurge(monthly, surgeFile), [monthly, surgeFile]);
  const idx = useMemo(() => (surge ? filterIndex(surge) : null), [surge]);
  const series = useMemo(() => buildSeries(monthly, surge, view, generatedAt), [monthly, surge, view, generatedAt]);
  const points = series.points;
  const n = points.length;
  const stacked = view.stack && view.count === 'published' && series.filtersReady;
  const log = view.log && !stacked;
  const overlays = visibleOverlays(view, series);
  const sel = activeCnas(view, idx);
  const filtersOff = view.count === 'reserved';
  const filterNote = filtersOff
    ? 'Filters count published CVEs. Switch Count to Published to use them.'
    : surgeProp === null
      ? 'Loading the filters…'
      : !series.filtersReady
        ? 'Filters arrive with the next hourly data update.'
        : '';
  const bands = SEVERITY_BANDS.map((b, k) => ({ b, k })).filter(({ b }) => !view.sev.length || view.sev.includes(b));

  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const [via, setVia] = useState<'mouse' | 'touch' | 'key'>('mouse');
  const [drag, setDrag] = useState<{ a: number; b: number } | null>(null);
  const [busy, setBusy] = useState<string>('');
  const wrap = useRef<HTMLElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const down = useRef<{ x: number; y: number; type: string; i: number; dragging: boolean } | null>(null);
  const suppressClick = useRef(false);
  const beforeZoom = useRef<View['preset']>('all');

  // A new series (a filter, a range) can be shorter: drop a pick that no longer exists.
  useEffect(() => {
    if (hover !== null && hover >= n) setHover(null);
  }, [n, hover]);

  const w = Math.max(0, width - M.l - M.r);
  const x = (i: number) => M.l + (n > 1 ? (i * w) / (n - 1) : w / 2);
  const last = points[n - 1];
  const cut = last?.partial && n > 1 ? n - 1 : n;
  const stackTops = useMemo(() => {
    if (!stacked) return [] as number[][];
    return points.map((p) => {
      let acc = 0;
      return bands.map(({ k }) => (acc += p.bands?.[k] ?? 0));
    });
  }, [points, stacked, bands.map((b) => b.b).join()]);
  const overlayValue = (p: Point, o: Overlay) => (o === 'kevpub' ? (p.kevpub ?? 0) : o === 'kevadd' ? p.kevadd : p.ai);
  let max = 0;
  for (const p of points) {
    max = Math.max(max, p.value);
    if (view.compare && p.prev !== null) max = Math.max(max, p.prev);
    for (const o of overlays) max = Math.max(max, overlayValue(p, o));
  }
  const showPace = view.group === 'month' && view.count === 'published' && !stacked && !!last?.partial;
  const pace = showPace && last ? onPace(last.value, series.progress) : null;
  const s = scale(pace === null ? max : Math.max(max, Math.min(pace, max * PACE_AXIS_HEADROOM)), M.t, H - M.b, log);
  const paceOff = pace !== null && s.y(pace) < M.t;
  const paceY = pace !== null ? Math.max(M.t, s.y(pace)) : 0;
  const pt = (v: number, i: number) => `${x(i).toFixed(1)} ${s.y(v).toFixed(1)}`;
  const path = (vals: readonly number[], upTo = cut) => vals.slice(0, upTo).map((v, i) => `${i ? 'L' : 'M'}${pt(v, i)}`).join('');
  const tail = (vals: readonly number[]) => (cut < n ? `M${pt(vals[n - 2], n - 2)}L${pt(vals[n - 1], n - 1)}` : '');
  const mainVals = points.map((p) => p.value);
  const prevVals = points.map((p) => p.prev);
  const partialLabel = last?.partial ? `${last.label} so far` : '';
  const ticks = xTicks(points, view.group, w);
  const dots = n <= 30;
  const h = hover !== null ? (points[hover] ?? null) : null;
  const hPartial = !!h?.partial;
  const yoy = h ? pointChange(h) : null;
  const countLabel = view.count === 'published' ? 'Published' : 'Reserved (by reservation month)';
  const words = filterWords(view, idx);

  // A tapped point stays picked until the next tap elsewhere on the page.
  useEffect(() => {
    if (via !== 'touch' || hover === null) return;
    const away = (e: PointerEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setHover(null);
    };
    document.addEventListener('pointerdown', away);
    return () => document.removeEventListener('pointerdown', away);
  }, [via, hover]);

  const at = (clientX: number, el: Element) => {
    const r = el.getBoundingClientRect();
    if (n <= 1) return 0;
    return Math.min(n - 1, Math.max(0, Math.round(((clientX - r.left - M.l) / Math.max(1, w)) * (n - 1))));
  };
  const onKey = (e: KeyboardEvent) => {
    const end = n - 1;
    const big = BIG_STEP[view.group];
    const moves: Record<string, (h: number | null) => number> = {
      ArrowRight: (h) => (h === null ? end : h + (e.shiftKey ? big : 1)),
      ArrowUp: (h) => (h === null ? end : h + 1),
      ArrowLeft: (h) => (h === null ? end : h - (e.shiftKey ? big : 1)),
      ArrowDown: (h) => (h === null ? end : h - 1),
      PageUp: (h) => (h ?? end) + big,
      PageDown: (h) => (h ?? end) - big,
      Home: () => 0,
      End: () => end,
    };
    const move = moves[e.key];
    if (move && n > 0) {
      e.preventDefault();
      e.stopPropagation();
      setVia('key');
      setHover((h) => Math.min(end, Math.max(0, move(h))));
    } else if (e.key === 'Escape' && (hover !== null || drag)) {
      e.stopPropagation();
      setHover(null);
      setDrag(null);
      down.current = null;
    }
  };

  const describe = (i: number) => {
    const p = points[i];
    if (!p) return '';
    const head = p.partial ? `${p.label} so far${view.group === 'month' ? `, ${series.progress.daysElapsed} of ${series.progress.daysInMonth} days` : ''}` : p.label;
    const c = pointChange(p);
    const parts = [`${fmtInt(p.value)} ${view.count}${words ? ` (${words})` : ''}${c !== null ? `, ${fmtChange(c)} vs ${p.partial ? 'the same point ' : ''}a year earlier` : ''}`];
    if (stacked) parts.push(bands.map(({ b, k }) => `${fmtInt(p.bands?.[k] ?? 0)} ${BAND_LABELS[b]}`).join(', '));
    for (const o of overlays) parts.push(`${fmtInt(overlayValue(p, o))} ${LINE[o].label}`);
    return `${head}: ${parts.join('; ')}.`;
  };

  const zoom = (a: number, b: number) => {
    if (a === b) return;
    if (!series.range.custom) beforeZoom.current = view.preset;
    setHover(null);
    set(zoomTo(view, points, a, b));
  };

  const toggleSev = (b: SeverityBand) => {
    const cur = view.sev.length ? view.sev : [...SEVERITY_BANDS];
    const next = cur.includes(b) ? cur.filter((x) => x !== b) : [...cur, b];
    set({ ...view, sev: next.length === 0 || next.length === SEVERITY_BANDS.length ? [] : SEVERITY_BANDS.filter((x) => next.includes(x)) });
  };
  const groupOut = (keys: readonly string[]) => keys.every((k) => view.cnaOut.includes(k));
  const toggleGroup = (keys: readonly string[]) => {
    const on = groupOut(keys);
    set({ ...view, cnaOnly: null, cnaOut: on ? view.cnaOut.filter((k) => !keys.includes(k)) : [...view.cnaOut, ...keys.filter((k) => !view.cnaOut.includes(k))] });
  };
  const has = (keys: readonly string[]) => !!idx && keys.every((k) => idx.byKey.has(k));
  const onCna = (value: string) => {
    if (value === '') set({ ...view, cnaOnly: null });
    else if (value.startsWith('-')) set({ ...view, cnaOnly: null, cnaOut: view.cnaOut.includes(value.slice(1)) ? view.cnaOut : [...view.cnaOut, value.slice(1)] });
    else set({ ...view, cnaOnly: value.slice(1), cnaOut: [] });
  };
  const toggleLine = (o: Overlay) => set({ ...view, lines: view.lines.includes(o) ? view.lines.filter((x) => x !== o) : [...view.lines, o] });

  const first = monthly[0]?.month ?? '1999-01';
  const lastMonth = monthly[monthly.length - 1]?.month ?? first;
  const fromValue = points[0]?.first ?? first;
  const toValue = last?.last ?? lastMonth;
  const onMonth = (end: 'from' | 'to', raw: string) => {
    if (!/^\d{4}-\d{2}$/.test(raw)) return;
    const v = raw < first ? first : raw > lastMonth ? lastMonth : raw;
    if (!series.range.custom) beforeZoom.current = view.preset;
    const next = { ...view, from: end === 'from' ? v : fromValue, to: end === 'to' ? v : toValue };
    if (next.from > next.to) next.from = next.to = v;
    set(next);
  };

  const legend: { label: string; cls: string; dashed?: boolean }[] = [
    ...(stacked ? bands.map(({ b }) => ({ label: BAND_LABELS[b], cls: `s-sev s-sev--${b}` })) : [{ label: `${countLabel}${words ? `: ${words}` : ''}`, cls: 's-volume' }]),
    ...(view.compare ? [{ label: 'A year earlier', cls: 's-volume', dashed: true }] : []),
    ...overlays.map((o) => ({ label: LINE[o].label, cls: LINE[o].cls })),
  ];

  const cols = csvColumns(view, series);
  const tableCols = cols.slice(4);
  const rangeWords = n === 1 ? partialLabel || last.label : n ? `${points[0].label} to ${partialLabel || last.label}` : '';
  const total = points.reduce((a, p) => a + p.value, 0);
  const busiest = busiestPoint(points);
  const prevTotal = points.every((p) => p.prev !== null) ? points.reduce((a, p) => a + (p.prev ?? 0), 0) : null;
  const summary = n
    ? `${rangeWords}, by ${GROUP_NOUN[view.group]}: ${fmtInt(total)} CVEs ${view.count === 'reserved' ? 'reserved' : 'published'}${words ? `, ${words}` : ''}.${busiest ? ` Busiest ${GROUP_NOUN[view.group]}: ${busiest.partial ? `${busiest.label} so far` : busiest.label}, with ${fmtInt(busiest.value)}.` : ''}${prevTotal && prevTotal > 0 ? ` ${fmtChange(total / prevTotal - 1)} on the same period a year earlier.` : ''}`
    : 'No months in this range.';

  // A dashed swatch is a gradient of currentColor, so its colour is `color`; a solid one is its background.
  const colorOf = (cls: string, dashed?: boolean) => {
    const el = wrap.current?.querySelector(`.legend__line.${cls.split(' ').pop()}${dashed ? '.legend__line--dashed' : ':not(.legend__line--dashed)'}`);
    return el ? getComputedStyle(el)[dashed ? 'color' : 'backgroundColor'] : '#888';
  };
  const onCsv = () => downloadBlob(new Blob([toCsv(points, cols)], { type: 'text/csv;charset=utf-8' }), exportName(points, view, 'csv'));
  const onPng = async () => {
    if (!svgRef.current) return;
    setBusy('Making the PNG.');
    try {
      await downloadPng(
        svgRef.current,
        {
          title: `CVEs per ${GROUP_NOUN[view.group]}${words ? `: ${words}` : ''}`,
          subtitle: `${rangeWords}. ${view.count === 'published' ? 'By datePublished' : 'By dateReserved'}${log ? ', log scale' : ''}.`,
          legend: legend.map((l) => ({ label: l.label, color: colorOf(l.cls, l.dashed), dashed: l.dashed })),
          footer: `cverdict.dev/surge · data as of ${generatedAt.slice(0, 16).replace('T', ' ')} UTC`,
        },
        exportName(points, view, 'png'),
      );
      setBusy('');
    } catch {
      setBusy('The PNG could not be made in this browser. The CSV still works.');
    }
  };

  const showReset = series.range.custom;
  const presetOn = series.range.custom ? null : view.preset;

  return (
    <figure class="chart mc" ref={wrap}>
      <div class="mc__ctrls">
        <div class="mc__row">
          <div class="seg seg--sm" role="group" aria-label="Date range">
            {PRESETS.map((p) => (
              <button key={p.id} type="button" class="seg__btn" aria-pressed={presetOn === p.id ? 'true' : 'false'} onClick={() => set(withPreset(view, p.id))}>
                {p.id === 'all' ? 'All since 1999' : p.label}
              </button>
            ))}
          </div>
          <div class="mc__months">
            <label class="select mc__field">
              <span>From</span>
              <input type="month" value={fromValue} min={first} max={lastMonth} onChange={(e) => onMonth('from', (e.currentTarget as HTMLInputElement).value)} />
            </label>
            <label class="select mc__field">
              <span>To</span>
              <input type="month" value={toValue} min={first} max={lastMonth} onChange={(e) => onMonth('to', (e.currentTarget as HTMLInputElement).value)} />
            </label>
            {/* Kept in the layout while hidden, so the row does not move when a zoom starts. */}
            <button type="button" class={`btn btn--sm btn--ghost mc__reset${showReset ? '' : ' is-off'}`} onClick={() => set(withPreset(view, beforeZoom.current))} aria-hidden={showReset ? undefined : 'true'} tabIndex={showReset ? 0 : -1}>
              Reset zoom
            </button>
          </div>
        </div>
        <div class="mc__row">
          <Seg label="Group by" value={view.group} options={(['month', 'quarter', 'year'] as const).map((g) => ({ id: g, label: GROUP_LABEL[g] }))} onPick={(g) => set({ ...view, group: g })} />
          <Seg label="Count" value={view.count} options={[{ id: 'published', label: 'Published' }, { id: 'reserved', label: 'Reserved' }] as const} onPick={(c) => set({ ...view, count: c })} />
          <Seg label="Scale" value={log ? 'log' : 'linear'} options={[{ id: 'linear', label: 'Linear' }, { id: 'log', label: 'Log' }] as const} onPick={(v) => set({ ...view, log: v === 'log' })} disabled={stacked} />
          <Toggle on={view.compare} onClick={() => set({ ...view, compare: !view.compare })} label="A year earlier" tip="Dashed line: the same period one year earlier" />
        </div>
        <fieldset class="mc__row mc__filters" disabled={filtersOff || !series.filtersReady}>
          <legend class="sr-only">Filters</legend>
          <div class="seg seg--sm" role="group" aria-label="Severity (CVSS)">
            {SEVERITY_BANDS.map((b) => (
              <button key={b} type="button" class={`seg__btn mc__sev mc__sev--${b}`} aria-pressed={!view.sev.length || view.sev.includes(b) ? 'true' : 'false'} onClick={() => toggleSev(b)}>
                <span class={`mc__dot s-sev s-sev--${b}`} aria-hidden="true" />
                {b === 'none' ? 'None' : BAND_LABELS[b]}
              </button>
            ))}
          </div>
          <Toggle on={stacked} onClick={() => set({ ...view, stack: !view.stack })} label="Stack by severity" />
          <label class="select mc__field mc__cna">
            <span>CNA</span>
            <select value={view.cnaOnly ? `+${view.cnaOnly}` : ''} onChange={(e) => onCna((e.currentTarget as HTMLSelectElement).value)}>
              <option value="">All CNAs</option>
              {idx && (
                <optgroup label="Only one CNA">
                  {idx.cnas.map((c) => (
                    <option key={`+${c.key}`} value={`+${c.key}`}>
                      Only {c.label}
                    </option>
                  ))}
                </optgroup>
              )}
              {idx && (
                <optgroup label="Leave one out">
                  {idx.cnas.map((c) => (
                    <option key={`-${c.key}`} value={`-${c.key}`} disabled={view.cnaOut.includes(c.key)}>
                      Exclude {c.label}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </label>
          {(has(WORDPRESS_CNAS) || !idx) && <Toggle on={groupOut(WORDPRESS_CNAS)} onClick={() => toggleGroup(WORDPRESS_CNAS)} label="Exclude WordPress" tip="Wordfence, WPScan and Patchstack, the WordPress plugin CNAs" />}
          {(has(KERNEL_CNAS) || !idx) && <Toggle on={groupOut(KERNEL_CNAS)} onClick={() => toggleGroup(KERNEL_CNAS)} label="Exclude Linux kernel" tip="The Linux kernel CNA" />}
          <Toggle on={view.kev} onClick={() => set({ ...view, kev: !view.kev })} label="In CISA KEV only" tip="CVEs CISA lists as known exploited, by the month the CVE was published" />
        </fieldset>
        {/* Always there, one line tall at least, so a note or chip coming and going moves nothing below. */}
        {(
          <div class="mc__row mc__notes">
            {!filtersOff &&
              idx &&
              outChips(sel.out.map((i) => idx.cnas[i])).map((c) => (
                <button key={c.label} type="button" class="activechip" onClick={() => set({ ...view, cnaOut: view.cnaOut.filter((k) => !c.keys.includes(k)) })} aria-label={`Stop excluding ${c.label}`}>
                  Excluding <strong>{c.label}</strong> ×
                </button>
              ))}
            {filterNote && <span class="mc__note mc__note--why" role="status">{filterNote}</span>}
            {stacked && view.log && <span class="mc__note">Log scale is off while stacked.</span>}
            <span class="mc__hint">Drag across the chart to zoom.</span>
          </div>
        )}
      </div>
      <div class="chart__bar">
        <ul class="legend legend--inline">
          {legend.map((l) => (
            <li key={l.label} class="legend__item">
              <span class={`legend__line ${l.cls}${l.dashed ? ' legend__line--dashed' : ''}`} />
              {l.label}
            </li>
          ))}
        </ul>
        <div class="chart__ctrls mc__lines" role="group" aria-label="Lines">
          {(['kevpub', 'kevadd', 'ai'] as const).map((o) => (
            <Toggle
              key={o}
              on={view.lines.includes(o)}
              onClick={() => toggleLine(o)}
              label={o === 'kevpub' ? 'In KEV' : o === 'kevadd' ? 'KEV added' : 'AI'}
              disabled={o === 'kevpub' ? !series.filtersReady || filtersOff || view.kev : series.narrowed}
              tip={o === 'kevpub' ? 'CVEs in CISA KEV, by publication month. Follows the filters.' : o === 'kevadd' ? 'CISA KEV additions by listing month. Counts every CVE, so it hides while a filter is on.' : 'AI-credited CVEs. Counts every CVE, so it hides while a filter is on.'}
            />
          ))}
        </div>
      </div>
      <div class="chart__plot" ref={ref} style={{ height: `${H}px` }}>
        {width > 0 && (
          <svg
            ref={svgRef}
            width={width}
            height={H}
            class="chart__svg"
            tabIndex={0}
            role="slider"
            aria-label={`CVEs per ${GROUP_NOUN[view.group]}, ${rangeWords}`}
            aria-describedby="monthly-desc"
            aria-valuemin={1}
            aria-valuemax={Math.max(1, n)}
            aria-valuenow={(hover ?? n - 1) + 1}
            aria-valuetext={hover !== null ? describe(hover) : `No ${GROUP_NOUN[view.group]} picked. Use the arrow keys to pick one.`}
            onKeyDown={onKey}
            onBlur={() => {
              if (via !== 'touch') setHover(null);
            }}
            onPointerDown={(e) => {
              if (e.button !== 0) return;
              down.current = { x: e.clientX, y: e.clientY, type: e.pointerType, i: at(e.clientX, e.currentTarget), dragging: false };
              suppressClick.current = false;
              // A tap picks without focusing, so no keyboard focus ring shows; the tap away clears it.
              if (e.pointerType === 'touch') e.preventDefault();
            }}
            onPointerMove={(e) => {
              const d = down.current;
              if (d) {
                const dx = e.clientX - d.x;
                if (!d.dragging && Math.abs(dx) > 8 && Math.abs(dx) > Math.abs(e.clientY - d.y)) {
                  d.dragging = true;
                  e.currentTarget.setPointerCapture?.(e.pointerId);
                }
                if (d.dragging) {
                  setHover(null);
                  setDrag({ a: d.i, b: at(e.clientX, e.currentTarget) });
                  return;
                }
              }
              // Touch has no hover: a finger moving up or down over the chart is scrolling the page.
              if (e.pointerType === 'touch') return;
              setVia('mouse');
              setHover(at(e.clientX, e.currentTarget));
            }}
            onPointerUp={(e) => {
              const d = down.current;
              if (d?.dragging) {
                suppressClick.current = true;
                down.current = null;
                const b = at(e.clientX, e.currentTarget);
                setDrag(null);
                zoom(d.i, b);
              }
            }}
            onPointerCancel={() => {
              down.current = null;
              setDrag(null);
            }}
            onPointerLeave={(e) => {
              if (e.pointerType !== 'touch' && via === 'mouse' && !down.current?.dragging) setHover(null);
            }}
            onClick={(e) => {
              const d = down.current;
              down.current = null;
              if (suppressClick.current) {
                suppressClick.current = false;
                return;
              }
              if (!d || d.type !== 'touch' || Math.hypot(e.clientX - d.x, e.clientY - d.y) > 8) return;
              setVia('touch');
              setHover(at(e.clientX, e.currentTarget));
            }}
          >
            {s.ticks.map((t) => (
              <g key={t} class="chart__grid">
                <line x1={M.l} x2={width - M.r} y1={s.y(t)} y2={s.y(t)} />
                <text x={M.l - 8} y={s.y(t)} text-anchor="end" dominant-baseline="middle">
                  {fmtCompact(t)}
                </text>
              </g>
            ))}
            {ticks.map((p) => (
              <text key={p.i} class="chart__xlabel" x={x(p.i)} y={H - 8} text-anchor={n === 1 ? 'middle' : p.i === 0 && x(p.i) - M.l < 20 ? 'start' : 'middle'}>
                {p.label}
              </text>
            ))}
            {stacked ? (
              <g class="mc__stack">
                {bands.map(({ b }, j) => {
                  const top = stackTops.map((t) => t[j]);
                  const bottom = stackTops.map((t) => (j ? t[j - 1] : 0));
                  const upTo = Math.max(1, cut);
                  const d =
                    n > 1
                      ? `${path(top, upTo)}${bottom
                          .slice(0, upTo)
                          .map((v, i) => `L${pt(v, i)}`)
                          .reverse()
                          .join('')}Z`
                      : '';
                  return (
                    <g key={b}>
                      {d && <path class={`mc__band s-sev s-sev--${b}`} d={d} />}
                      {cut < n && <path class={`chart__line chart__line--partial s-sev s-sev--${b}`} d={tail(top)} />}
                    </g>
                  );
                })}
              </g>
            ) : (
              <>
                {n > 1 && <path class="chart__area s-volume" d={`${path(mainVals)}L${x(Math.max(0, cut - 1))} ${s.y(0)}L${x(0)} ${s.y(0)}Z`} />}
                <path class="chart__line s-volume" d={path(mainVals)} />
              </>
            )}
            {view.compare && (
              <path
                class="chart__line chart__line--prev s-volume"
                d={prevVals
                  .map((v, i) => (v === null ? null : { v, i }))
                  .filter((p): p is { v: number; i: number } => p !== null)
                  .map((p, k) => `${k ? 'L' : 'M'}${pt(p.v, p.i)}`)
                  .join('')}
              />
            )}
            {overlays.map((o) => (
              <path key={o} class={`chart__line ${LINE[o].cls}`} d={path(points.map((p) => overlayValue(p, o)))} />
            ))}
            {dots && (
              <g class="mc__dots">
                {points.slice(0, cut).map((p, i) => (
                  <circle key={p.key} class={stacked ? 's-sev s-sev--critical' : 's-volume'} cx={x(i)} cy={s.y(stacked ? (stackTops[i]?.[bands.length - 1] ?? 0) : p.value)} r={2.5} />
                ))}
              </g>
            )}
            {cut < n && (
              <g class="chart__partial">
                {!stacked && <path class="chart__line chart__line--partial s-volume" d={tail(mainVals)} />}
                {overlays.map((o) => (
                  <path key={o} class={`chart__line chart__line--partial ${LINE[o].cls}`} d={tail(points.map((p) => overlayValue(p, o)))} />
                ))}
                {pace !== null && (
                  <g class="chart__pace">
                    <line x1={x(n - 1) + PACE_DX} x2={x(n - 1) + PACE_DX} y1={s.y(last.value)} y2={paceY} />
                    <circle cx={x(n - 1) + PACE_DX} cy={paceY} r={3.5} />
                  </g>
                )}
                {!stacked && <circle class="chart__hollow s-volume" cx={x(n - 1)} cy={s.y(last.value)} r={3.5} />}
                {overlays.map((o) => (
                  <circle key={o} class={`chart__hollow ${LINE[o].cls}`} cx={x(n - 1)} cy={s.y(overlayValue(last, o))} r={3.5} />
                ))}
              </g>
            )}
            {drag && drag.a !== drag.b && (
              <rect class="mc__drag" data-export="skip" x={Math.min(x(drag.a), x(drag.b))} y={M.t} width={Math.abs(x(drag.b) - x(drag.a))} height={H - M.b - M.t} />
            )}
            {h && hover !== null && (
              <g class="chart__cross" data-export="skip">
                <line x1={x(hover)} x2={x(hover)} y1={M.t} y2={H - M.b} />
                {!stacked && <circle class={`s-volume${hPartial ? ' is-hollow' : ''}`} cx={x(hover)} cy={s.y(h.value)} r={4} />}
                {stacked && <circle class={`s-sev s-sev--critical${hPartial ? ' is-hollow' : ''}`} cx={x(hover)} cy={s.y(stackTops[hover]?.[bands.length - 1] ?? 0)} r={4} />}
                {overlays.map((o) => (
                  <circle key={o} class={`${LINE[o].cls}${hPartial ? ' is-hollow' : ''}`} cx={x(hover)} cy={s.y(overlayValue(h, o))} r={4} />
                ))}
              </g>
            )}
          </svg>
        )}
        {h && hover !== null && !drag && (
          <div class={`chart__tip${x(hover) > width - 220 ? ' is-left' : ''}`} style={{ left: `${x(hover)}px` }} aria-hidden="true">
            <div class="chart__tip-head">{hPartial ? `${h.label} so far` : h.label}</div>
            {hPartial && view.group === 'month' && (
              <div class="chart__tip-row chart__tip-row--muted">
                <span />
                <strong>{series.progress.daysElapsed}</strong>
                <span>of {series.progress.daysInMonth} days</span>
              </div>
            )}
            {stacked &&
              [...bands].reverse().map(({ b, k }) => (
                <div key={b} class="chart__tip-row">
                  <span class={`legend__line s-sev s-sev--${b}`} />
                  <strong>{fmtInt(h.bands?.[k] ?? 0)}</strong>
                  <span>{BAND_LABELS[b]}</span>
                </div>
              ))}
            <div class="chart__tip-row">
              <span class={stacked ? '' : 'legend__line s-volume'} />
              <strong>{fmtInt(h.value)}</strong>
              <span>{stacked ? 'Total' : view.count === 'published' ? (series.narrowed ? 'Published, filtered' : 'Published') : 'Reserved'}</span>
            </div>
            {view.compare && h.prev !== null && (
              <div class="chart__tip-row chart__tip-row--muted">
                <span class="legend__line legend__line--dashed s-volume" />
                <strong>{fmtInt(h.prev)}</strong>
                <span>{hPartial ? 'Same point, a year earlier' : 'A year earlier'}</span>
              </div>
            )}
            {overlays.map((o) => (
              <div key={o} class="chart__tip-row">
                <span class={`legend__line ${LINE[o].cls}`} />
                <strong>{fmtInt(overlayValue(h, o))}</strong>
                <span>{LINE[o].label}</span>
              </div>
            ))}
            {!series.narrowed && view.count === 'published' && (
              <div class="chart__tip-row chart__tip-row--muted">
                <span />
                <strong>{fmtInt(h.rejected)}</strong>
                <span>Rejected</span>
              </div>
            )}
            {yoy !== null && (
              <div class="chart__tip-yoy">
                <strong>{fmtChange(yoy)}</strong> vs {hPartial ? 'the same point in ' : ''}
                {prevLabel(h, view.group).replace(/ (?=\S+$)/, ' ')}
              </div>
            )}
            {hPartial && pace !== null && (
              <div class="chart__tip-pace">
                On pace for about {fmtInt(pace)} (estimate){paceOff ? ', above the top of the chart' : ''}
              </div>
            )}
          </div>
        )}
      </div>
      <figcaption class="chart__take mc__summary">{summary}</figcaption>
      <div class="mc__export">
        <button type="button" class="btn btn--sm" onClick={onCsv} disabled={!n}>
          Download CSV
        </button>
        <button type="button" class="btn btn--sm" onClick={onPng} disabled={!n || width === 0}>
          Download PNG
        </button>
        <span class="mc__note" role="status">
          {busy}
        </span>
      </div>
      <p class="sr-only" id="monthly-desc">
        {`${summary}${last?.partial ? ` The last ${GROUP_NOUN[view.group]}, ${partialLabel}, is partial and drawn dashed.${pace !== null ? ` On pace for about ${fmtInt(pace)} (estimate).` : ''}` : ''} Use the arrow keys to move, Shift with an arrow to move further, and Escape to clear. The date range, grouping and filters are above the chart.`}
      </p>
      {/* Keyboard moves are announced by aria-valuetext; this reads out pointer hover and taps. */}
      <div class="sr-only" aria-live="polite">
        {hover !== null && via !== 'key' ? describe(hover) : ''}
      </div>
      <details class="chart__table">
        <summary>View as table</summary>
        <div class="tablewrap">
          <table class="table table--compact">
            <thead>
              <tr>
                <th scope="col">{GROUP_LABEL[view.group]}</th>
                {tableCols.map((c) => (
                  <th key={c.head} scope="col" class="num">
                    {columnLabel(c.head)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...points].reverse().map((p) => (
                <tr key={p.key}>
                  <th scope="row" class="chart__month">
                    {p.label}
                    {p.partial && (
                      <span class="muted">
                        {' '}
                        so far{view.group === 'month' && <span class="chart__days"> ({series.progress.daysElapsed} of {series.progress.daysInMonth} days)</span>}
                      </span>
                    )}
                  </th>
                  {tableCols.map((c) => {
                    const v = c.get(p);
                    return (
                      <td key={c.head} class="num">
                        {typeof v === 'number' ? fmtInt(v) : v === null ? '' : v}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}

/** One chip per excluded CNA, but one for the whole WordPress group when all three are out. */
function outChips(cnas: readonly { key: string; label: string }[]): { label: string; keys: string[] }[] {
  const keys = cnas.map((c) => c.key);
  const wp = WORDPRESS_CNAS.every((k) => keys.includes(k));
  const chips = wp ? [{ label: 'WordPress', keys: [...WORDPRESS_CNAS] }] : [];
  for (const c of cnas) if (!(wp && WORDPRESS_CNAS.includes(c.key))) chips.push({ label: c.label, keys: [c.key] });
  return chips;
}

/** The table header for a CSV column. */
function columnLabel(head: string): string {
  const band = (SEVERITY_BANDS as readonly string[]).includes(head) ? BAND_LABELS[head as SeverityBand] : null;
  if (band) return band;
  const labels: Record<string, string> = {
    published: 'Published',
    reserved: 'Reserved',
    published_year_earlier: 'A year earlier',
    reserved_year_earlier: 'A year earlier',
    in_kev_by_publication: 'In KEV',
    added_to_kev: 'KEV added',
    ai_credited: 'AI-credited',
  };
  return labels[head] ?? head;
}

/** The bucket a year before a point: "Nov 2025", "Q4 2025", "2025". */
function prevLabel(p: Point, group: Group): string {
  const y = Number(p.key.slice(0, 4)) - 1;
  if (group === 'month') return fmtMonth(`${y}${p.key.slice(4)}`);
  return bucketLabel(`${y}${p.key.slice(4)}`, group);
}
