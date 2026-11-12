/** The Surge: CVE volume since 1999, the window day by day, and who publishes it. */
import { useMemo, useState } from 'preact/hooks';
import type { StatsFile } from '../../../shared/contract';
import { ErrorState, Loading } from '../components/States';
import { data } from '../data';
import { cnaName, fmtCompact, fmtDate, fmtInt, fmtMonth, fmtPct } from '../format';
import { useData, useTitle, useWidth } from '../hooks';
import { href } from '../router';

type Month = StatsFile['monthly'][number];
type SeriesKey = 'published' | 'reserved' | 'kev_added' | 'ai';

const SERIES: Readonly<Record<SeriesKey, { label: string; cls: string }>> = {
  published: { label: 'Published', cls: 's-volume' },
  reserved: { label: 'Reserved (by reservation month)', cls: 's-volume' },
  kev_added: { label: 'Added to CISA KEV', cls: 's-kev' },
  ai: { label: 'AI-credited', cls: 's-ai' },
};

function niceStep(raw: number): number {
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(raw, 1e-9))));
  const f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
}

interface Scale {
  y: (v: number) => number;
  ticks: number[];
}

function scale(max: number, top: number, bottom: number, log: boolean): Scale {
  if (log) {
    const hi = Math.ceil(Math.log10(Math.max(10, max)));
    const y = (v: number) => bottom - (Math.log10(Math.max(0, v) + 1) / hi) * (bottom - top);
    return { y, ticks: Array.from({ length: hi + 1 }, (_, i) => Math.pow(10, i)) };
  }
  const step = niceStep(max / 4);
  const hi = Math.ceil(max / step) * step;
  return { y: (v: number) => bottom - (v / hi) * (bottom - top), ticks: Array.from({ length: Math.round(hi / step) + 1 }, (_, i) => i * step) };
}

function MonthlyChart({ monthly }: { monthly: readonly Month[] }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [log, setLog] = useState(false);
  const [volume, setVolume] = useState<'published' | 'reserved'>('published');
  const [hover, setHover] = useState<number | null>(null);
  const series: SeriesKey[] = [volume, 'kev_added', 'ai'];
  const H = 300;
  const M = { l: 48, r: 14, t: 14, b: 26 };
  const n = monthly.length;
  const w = Math.max(0, width - M.l - M.r);
  const x = (i: number) => M.l + (n > 1 ? (i * w) / (n - 1) : 0);
  const max = Math.max(...monthly.map((m) => Math.max(m[volume], m.kev_added, m.ai)));
  const s = scale(max, M.t, H - M.b, log);
  const path = (k: SeriesKey) => monthly.map((m, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${s.y(m[k]).toFixed(1)}`).join('');
  // Year labels every 5 years (10 when narrow) plus the current year, dropping any that would touch.
  const every = w < 480 ? 10 : 5;
  const years: { i: number; y: string }[] = [];
  monthly.forEach((m, i) => {
    const y = m.month.slice(0, 4);
    if (m.month.slice(5) !== '01' || (Number(y) % every !== 0 && y !== monthly[n - 1].month.slice(0, 4))) return;
    if (years.length && x(i) - x(years[years.length - 1].i) < 40) return;
    years.push({ i, y });
  });
  const h = hover !== null ? monthly[hover] : null;

  const onMove = (e: PointerEvent) => {
    const r = (e.currentTarget as SVGElement).getBoundingClientRect();
    setHover(Math.min(n - 1, Math.max(0, Math.round(((e.clientX - r.left - M.l) / Math.max(1, w)) * (n - 1)))));
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault();
    const step = e.shiftKey ? 12 : 1;
    setHover((cur) => Math.min(n - 1, Math.max(0, (cur ?? n - 1) + (e.key === 'ArrowRight' ? step : -step))));
  };

  return (
    <figure class="chart">
      <div class="chart__bar">
        <ul class="legend legend--inline">
          {series.map((k) => (
            <li key={k} class="legend__item">
              <span class={`legend__line ${SERIES[k].cls}`} />
              {SERIES[k].label}
            </li>
          ))}
        </ul>
        <div class="chart__ctrls">
          <div class="seg seg--sm" role="group" aria-label="Volume series">
            {(['published', 'reserved'] as const).map((v) => (
              <button key={v} type="button" class="seg__btn" aria-pressed={volume === v ? 'true' : 'false'} onClick={() => setVolume(v)}>
                {v === 'published' ? 'Published' : 'Reserved'}
              </button>
            ))}
          </div>
          <div class="seg seg--sm" role="group" aria-label="Scale">
            {[false, true].map((v) => (
              <button key={String(v)} type="button" class="seg__btn" aria-pressed={log === v ? 'true' : 'false'} onClick={() => setLog(v)}>
                {v ? 'Log' : 'Linear'}
              </button>
            ))}
          </div>
        </div>
      </div>
      <div class="chart__plot" ref={ref}>
        {width > 0 && (
          <svg width={width} height={H} role="img" aria-label={`CVEs ${volume} per month since 1999, with CISA KEV additions and AI-credited CVEs. Peak: ${fmtInt(max)}. Use arrow keys to read months.`} tabIndex={0} onKeyDown={onKey} onBlur={() => setHover(null)} onPointerMove={onMove} onPointerLeave={() => setHover(null)}>
            {s.ticks.map((t) => (
              <g key={t} class="chart__grid">
                <line x1={M.l} x2={width - M.r} y1={s.y(t)} y2={s.y(t)} />
                <text x={M.l - 8} y={s.y(t)} text-anchor="end" dominant-baseline="middle">
                  {fmtCompact(t)}
                </text>
              </g>
            ))}
            {years.map((p) => (
              <text key={p.i} class="chart__xlabel" x={x(p.i)} y={H - 8} text-anchor="middle">
                {p.y}
              </text>
            ))}
            <path class={`chart__area ${SERIES[volume].cls}`} d={`${path(volume)}L${x(n - 1)} ${s.y(0)}L${x(0)} ${s.y(0)}Z`} />
            {series.map((k) => (
              <path key={k} class={`chart__line ${SERIES[k].cls}`} d={path(k)} />
            ))}
            {hover !== null && (
              <g class="chart__cross">
                <line x1={x(hover)} x2={x(hover)} y1={M.t} y2={H - M.b} />
                {series.map((k) => (
                  <circle key={k} class={SERIES[k].cls} cx={x(hover)} cy={s.y(monthly[hover][k])} r={4} />
                ))}
              </g>
            )}
          </svg>
        )}
        {h && hover !== null && (
          <div class={`chart__tip${x(hover) > width - 220 ? ' is-left' : ''}`} style={{ left: `${x(hover)}px` }} aria-live="polite">
            <div class="chart__tip-head">{fmtMonth(h.month)}</div>
            {series.map((k) => (
              <div key={k} class="chart__tip-row">
                <span class={`legend__line ${SERIES[k].cls}`} />
                <strong>{fmtInt(h[k])}</strong>
                <span>{SERIES[k].label}</span>
              </div>
            ))}
            <div class="chart__tip-row chart__tip-row--muted">
              <span />
              <strong>{fmtInt(h.rejected)}</strong>
              <span>Rejected</span>
            </div>
          </div>
        )}
      </div>
      <details class="chart__table">
        <summary>View as table</summary>
        <div class="tablewrap">
          <table class="table table--compact">
            <thead>
              <tr>
                <th scope="col">Month</th>
                <th scope="col" class="num">Published</th>
                <th scope="col" class="num">Reserved</th>
                <th scope="col" class="num">Rejected</th>
                <th scope="col" class="num">KEV added</th>
                <th scope="col" class="num">AI-credited</th>
              </tr>
            </thead>
            <tbody>
              {[...monthly].reverse().map((m) => (
                <tr key={m.month}>
                  <th scope="row">{m.month}</th>
                  <td class="num">{fmtInt(m.published)}</td>
                  <td class="num">{fmtInt(m.reserved)}</td>
                  <td class="num">{fmtInt(m.rejected)}</td>
                  <td class="num">{fmtInt(m.kev_added)}</td>
                  <td class="num">{fmtInt(m.ai)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}

function Columns({ days, k, cls, label, height }: { days: StatsFile['daily']; k: 'published' | 'passed'; cls: string; label: string; height: number }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const M = { l: 48, r: 14, t: 10, b: 22 };
  const n = days.length;
  const slot = Math.max(1, (width - M.l - M.r) / Math.max(1, n));
  const bar = Math.max(2, Math.min(24, slot - 2));
  const max = Math.max(1, ...days.map((d) => d[k]));
  const s = scale(max, M.t, height - M.b, false);
  const h = hover !== null ? days[hover] : null;
  return (
    <div class="chart__plot" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={`${label} per day in the window. Maximum ${fmtInt(max)}.`} onPointerLeave={() => setHover(null)}>
          {s.ticks.map((t) => (
            <g key={t} class="chart__grid">
              <line x1={M.l} x2={width - M.r} y1={s.y(t)} y2={s.y(t)} />
              <text x={M.l - 8} y={s.y(t)} text-anchor="end" dominant-baseline="middle">
                {fmtCompact(t)}
              </text>
            </g>
          ))}
          {days.map((d, i) => {
            const cx = M.l + i * slot + slot / 2;
            const y = s.y(d[k]);
            const y0 = s.y(0);
            const r = Math.min(4, bar / 2, Math.max(0, y0 - y));
            const monday = new Date(`${d.date}T00:00:00Z`).getUTCDay() === 1;
            return (
              <g key={d.date} class={`chart__col${hover === i ? ' is-hover' : ''}`} onPointerEnter={() => setHover(i)}>
                <rect class="chart__hit" x={cx - slot / 2} y={M.t} width={slot} height={height - M.t - M.b} />
                {d[k] > 0 && <path class={`chart__bar ${cls}${k === 'passed' && d.exploited ? ' has-exploited' : ''}`} d={`M${cx - bar / 2} ${y0}V${y + r}Q${cx - bar / 2} ${y} ${cx - bar / 2 + r} ${y}H${cx + bar / 2 - r}Q${cx + bar / 2} ${y} ${cx + bar / 2} ${y + r}V${y0}Z`} />}
                {monday && (
                  <text class="chart__xlabel" x={cx} y={height - 6} text-anchor="middle">
                    {fmtDate(d.date)}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      )}
      {h && hover !== null && (
        <div class={`chart__tip${hover > n * 0.7 ? ' is-left' : ''}`} style={{ left: `${M.l + hover * slot + slot / 2}px` }}>
          <div class="chart__tip-head">{fmtDate(h.date)}</div>
          <div class="chart__tip-row">
            <strong>{fmtInt(h.published)}</strong>
            <span>published</span>
          </div>
          <div class="chart__tip-row">
            <strong>{fmtInt(h.passed)}</strong>
            <span>passed</span>
          </div>
          <div class="chart__tip-row">
            <strong>{fmtInt(h.exploited)}</strong>
            <span>exploited</span>
          </div>
        </div>
      )}
    </div>
  );
}

function Tiles({ stats, ytd }: { stats: StatsFile; ytd: number }) {
  const m = stats.monthly;
  const last = m[m.length - 1];
  const year = Number(last.month.slice(0, 4));
  const monthIdx = Number(last.month.slice(5)) - 1;
  const asOf = new Date(stats.generated_at);
  const dayFrac = asOf.getUTCDate() / new Date(Date.UTC(year, monthIdx + 1, 0)).getUTCDate();
  const prev = m.filter((x) => x.month.startsWith(`${year - 1}-`));
  const prevSame = prev.slice(0, monthIdx).reduce((a, x) => a + x.published, 0) + (prev[monthIdx]?.published ?? 0) * dayFrac;
  const peak = m.reduce((a, x) => (x.published > a.published ? x : a), m[0]);
  const all = m.reduce((a, x) => a + x.published, 0);
  const tiles: { label: string; value: string; note: string }[] = [
    { label: `${year} so far`, value: fmtInt(ytd), note: prevSame > 0 ? `${ytd >= prevSame ? '+' : ''}${fmtPct(ytd / prevSame - 1)} vs the same days of ${year - 1}` : '' },
    { label: 'Busiest month ever', value: fmtInt(peak.published), note: fmtMonth(peak.month) },
    { label: `Share of all CVEs since 1999`, value: fmtPct(ytd / Math.max(1, all)), note: `published in ${year} alone` },
    { label: 'Added to KEV this year', value: fmtInt(m.filter((x) => x.month.startsWith(`${year}-`)).reduce((a, x) => a + x.kev_added, 0)), note: `about ${fmtPct(m.filter((x) => x.month.startsWith(`${year}-`)).reduce((a, x) => a + x.kev_added, 0) / Math.max(1, ytd))} of this year’s volume` },
  ];
  return (
    <ul class="tiles">
      {tiles.map((t) => (
        <li key={t.label} class="tile">
          <span class="tile__label">{t.label}</span>
          <span class="tile__value">{t.value}</span>
          <span class="tile__note">{t.note}</span>
        </li>
      ))}
    </ul>
  );
}

export default function Surge() {
  useTitle('The Surge');
  const stats = useData(data.stats);
  const meta = useData(data.meta);
  const cnas = useMemo(() => (stats.status === 'ready' ? stats.data.cnas : []), [stats]);
  const maxCna = Math.max(1, ...cnas.map((c) => c.count));
  return (
    <div class="page page--surge">
      <header class="page__head">
        <p class="eyebrow">Volume since 1999</p>
        <h1 class="page__title" tabIndex={-1}>
          The Surge
        </h1>
        <p class="page__lede">CVE volume tripled in a year while exploitation stayed rare. Most of the growth is long-tail software, WordPress plugins and kernel bug-fixes — volume is not risk.</p>
      </header>
      {stats.status === 'error' ? (
        <ErrorState error={stats.error} onRetry={stats.retry} />
      ) : stats.status !== 'ready' ? (
        <Loading label="Loading statistics" lines={4} height="80px" />
      ) : (
        <>
          <Tiles stats={stats.data} ytd={meta.status === 'ready' ? meta.data.counts.published_ytd : stats.data.monthly.filter((m) => m.month.startsWith(stats.data.monthly[stats.data.monthly.length - 1].month.slice(0, 4))).reduce((a, m) => a + m.published, 0)} />
          <section class="panel" aria-labelledby="monthly-h">
            <header class="panel__head">
              <div>
                <h2 id="monthly-h" class="panel__title">
                  CVEs per month
                </h2>
                <p class="panel__sub">By datePublished (or dateReserved). Switch to log scale to compare KEV additions and AI-credited CVEs on the same axis.</p>
              </div>
            </header>
            <MonthlyChart monthly={stats.data.monthly} />
          </section>
          <section class="panel" aria-labelledby="daily-h">
            <header class="panel__head">
              <div>
                <h2 id="daily-h" class="panel__title">
                  The last 30 days
                </h2>
                <p class="panel__sub">Published per day, and the few that passed at the default evidence bar. Same days, separate scales.</p>
              </div>
            </header>
            <figure class="chart">
              <figcaption class="chart__cap">Published</figcaption>
              <Columns days={stats.data.daily} k="published" cls="s-volume" label="CVEs published" height={170} />
              <figcaption class="chart__cap">Passed (exploited or likely)</figcaption>
              <Columns days={stats.data.daily} k="passed" cls="s-passed" label="CVEs passed" height={120} />
            </figure>
          </section>
          <div class="surge__grid">
            <section class="panel" aria-labelledby="cna-h">
              <header class="panel__head">
                <h2 id="cna-h" class="panel__title">
                  Who publishes the window
                </h2>
                <span class="panel__sub">top {cnas.length} CNAs</span>
              </header>
              <div class="tablewrap">
                <table class="table">
                  <thead>
                    <tr>
                      <th scope="col">CNA</th>
                      <th scope="col">CVEs</th>
                      <th scope="col" class="num">Passed</th>
                      <th scope="col" class="num" data-tip="Records without any CVSS score (CNA or CISA-ADP)">No CVSS</th>
                      <th scope="col" class="num" data-tip="Records CISA has not assessed with SSVC yet">No SSVC</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cnas.map((c) => (
                      <tr key={c.cna}>
                        <th scope="row">
                          <a href={`${href('explore')}?cna=${encodeURIComponent(c.cna)}`}>{cnaName(c.cna)}</a>
                        </th>
                        <td>
                          <span class="inlinebar">
                            <span class="inlinebar__fill" style={{ width: `${(c.count / maxCna) * 100}%` }} />
                            <span class="mono">{fmtInt(c.count)}</span>
                          </span>
                        </td>
                        <td class={`num${c.passed ? ' is-lit' : ''}`}>
                          {fmtInt(c.passed)} <span class="muted">{fmtPct(c.passed / Math.max(1, c.count))}</span>
                        </td>
                        <td class="num">{fmtPct(c.no_cvss / Math.max(1, c.count))}</td>
                        <td class="num">{fmtPct(c.ssvc_missing / Math.max(1, c.count))}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
            <section class="panel" aria-labelledby="ai-h">
              <header class="panel__head">
                <h2 id="ai-h" class="panel__title">
                  AI-credited discoveries
                </h2>
                <span class="panel__sub">{meta.status === 'ready' ? `${fmtInt(meta.data.counts.ai_credited_window)} in the window` : ''}</span>
              </header>
              <p class="panel__sub">Credits that name an AI system or lab. Information only: AI-found bugs are exploited at about the base rate.</p>
              <ol class="ranklist">
                {stats.data.ai_credits.map((a) => (
                  <li key={a.text}>
                    <span class="ranklist__text">“{a.text}”</span>
                    <span class="mono">{fmtInt(a.count)}</span>
                  </li>
                ))}
              </ol>
            </section>
          </div>
        </>
      )}
    </div>
  );
}
