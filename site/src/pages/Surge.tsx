/**
 * The Surge, told in order: the flood (volume since 1999), volume is not risk (KEV additions per
 * 1,000 CVEs), how fast CISA lists, the last 30 days, who publishes, and AI credits. Sections are
 * numbered like the brand diagrams and play their animations as they scroll into view.
 */
import type { ComponentChildren } from 'preact';
import { useMemo, useState } from 'preact/hooks';
import type { StatsFile } from '../../../shared/contract';
import { DailyChart } from '../components/DailyChart';
import { KevLagChart } from '../components/KevLagChart';
import { RiskGap } from '../components/RiskGap';
import { MonthlyChart } from '../components/MonthlyChart';
import { ErrorState, Loading } from '../components/States';
import { data } from '../data';
import { dailyAt, dailyTakeaway, kevByDay, lastDayPartial, type DayRow } from '../daily';
import { cnaName, fmtInt, fmtMonth, fmtPct } from '../format';
import { chartYears } from '../kevlag';
import { useCountUp, useData, useReveal, useTitle, useWidth } from '../hooks';
import { href } from '../router';
import { knob, useStore } from '../state';
import { LEDE_FALLBACK, busiestComplete, growth, kevGrowth, ledeText, riskRows, shiftMonth, windowLabel, type Growth } from '../surge';

function DailyTable({ days, kev, kevReady, partialLast }: { days: readonly DayRow[]; kev: ReadonlyMap<string, number>; kevReady: boolean; partialLast: boolean }) {
  return (
    <details class="chart__table">
      <summary>View as table</summary>
      <div class="tablewrap">
        <table class="table table--compact">
          <thead>
            <tr>
              <th scope="col">Day</th>
              <th scope="col" class="num">
                All CVEs
              </th>
              <th scope="col" class="num">
                Cleared the bar
              </th>
              <th scope="col" class="num">
                Exploited
              </th>
              {kevReady && (
                <th scope="col" class="num">
                  Added to KEV
                </th>
              )}
            </tr>
          </thead>
          <tbody>
            {[...days].reverse().map((d, i) => (
              <tr key={d.date}>
                <th scope="row" class="chart__month">
                  {d.date}
                  {i === 0 && partialLast && <span class="muted"> so far</span>}
                </th>
                <td class="num">{fmtInt(d.published)}</td>
                <td class="num">{fmtInt(d.passed)}</td>
                <td class="num">{fmtInt(d.exploited)}</td>
                {kevReady && <td class="num">{fmtInt(kev.get(d.date) ?? 0)}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

/** A number that counts up from zero when it first shows. */
function Num({ value, format }: { value: number; format: (v: number) => string }) {
  return <>{format(useCountUp(value, 900))}</>;
}

/** A numbered section, as in the brand diagrams: "01 The flood", then the panel title. */
function Section({ n, kicker, id, title, sub, aside, children, class: cls }: { n: string; kicker: string; id: string; title: string; sub?: ComponentChildren; aside?: ComponentChildren; children: ComponentChildren; class?: string }) {
  const ref = useReveal<HTMLElement>();
  return (
    <section class={`panel sect${cls ? ` ${cls}` : ''}`} aria-labelledby={id} ref={ref}>
      <header class="panel__head sect__head">
        <div>
          <p class="sect__kicker">
            <span class="sect__n mono">{n}</span>
            {kicker}
          </p>
          <h2 id={id} class="panel__title sect__title">
            {title}
          </h2>
          {sub && <p class="panel__sub">{sub}</p>}
        </div>
        {aside}
      </header>
      {children}
    </section>
  );
}

const SPARK_MONTHS = 36;

/** CVEs per month over three years, the growth window lit. Drawn in on load, in pixels so the dots stay round. */
function Spark({ stats, g }: { stats: StatsFile; g: Growth | null }) {
  const [ref, W] = useWidth<HTMLDivElement>();
  const rows = stats.monthly.slice(-SPARK_MONTHS);
  const H = 72;
  const max = Math.max(1, ...rows.map((r) => r.published));
  const x = (i: number) => 4 + (rows.length > 1 ? (i * (W - 8)) / (rows.length - 1) : (W - 8) / 2);
  const y = (v: number) => H - 3 - (v / max) * (H - 10);
  const line = rows.map((r, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(r.published).toFixed(1)}`).join('');
  const lit = g ? rows.map((r, i) => ({ r, i })).filter(({ r }) => r.month >= g.start && r.month <= g.end) : [];
  return (
    <div class="spark" ref={ref} aria-hidden="true">
      {W > 0 && (
        <svg width={W} height={H} focusable="false">
          <defs>
            <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stop-color="currentColor" stop-opacity="0.3" />
              <stop offset="1" stop-color="currentColor" stop-opacity="0" />
            </linearGradient>
          </defs>
          <path class="spark__area" d={`${line}L${x(rows.length - 1)} ${H}L${x(0)} ${H}Z`} fill="url(#spark-fill)" />
          <path class="spark__line" d={line} pathLength={1} />
          {lit.map(({ r, i }) => (
            <circle key={r.month} class="spark__dot" cx={x(i)} cy={y(r.published)} r={3.5} />
          ))}
        </svg>
      )}
    </div>
  );
}

function Hero({ stats, ytd }: { stats: StatsFile; ytd: number }) {
  const m = stats.monthly;
  const last = m[m.length - 1];
  const year = Number(last.month.slice(0, 4));
  const monthIdx = Number(last.month.slice(5)) - 1;
  const asOf = new Date(stats.generated_at);
  const dayFrac = asOf.getUTCDate() / new Date(Date.UTC(year, monthIdx + 1, 0)).getUTCDate();
  const prev = m.filter((x) => x.month.startsWith(`${year - 1}-`));
  const prevSame = prev.slice(0, monthIdx).reduce((a, x) => a + x.published, 0) + (prev[monthIdx]?.published ?? 0) * dayFrac;
  const peak = busiestComplete(m, stats.generated_at) ?? m[0];
  const all = m.reduce((a, x) => a + x.published, 0);
  const kevYear = m.filter((x) => x.month.startsWith(`${year}-`)).reduce((a, x) => a + x.kev_added, 0);
  const g = growth(m, stats.generated_at);
  const kg = kevGrowth(m, g);
  const tiles: { label: string; value: number; format: (v: number) => string; note: string }[] = [
    { label: `${year} so far`, value: ytd, format: fmtInt, note: prevSame > 0 ? `${ytd >= prevSame ? '+' : ''}${fmtPct(ytd / prevSame - 1)} vs the same days of ${year - 1}` : '' },
    { label: 'Busiest month ever', value: peak.published, format: fmtInt, note: fmtMonth(peak.month) },
    { label: 'Share of all CVEs since 1999', value: Math.round((ytd / Math.max(1, all)) * 100), format: (v) => `${v}%`, note: `published in ${year} alone` },
    { label: 'Added to KEV this year', value: kevYear, format: fmtInt, note: `about ${fmtPct(kevYear / Math.max(1, ytd))} of this year’s volume` },
  ];
  return (
    <div class="sh">
      {g && (
        <div class="sh__hero">
          <p class="sh__label">{windowLabel(g.start, g.end)}</p>
          <p class="sh__big">
            <Num value={Math.round(g.ratio * 10)} format={(v) => (v / 10).toFixed(1)} />
            <span class="sh__x">×</span>
          </p>
          <p class="sh__note">
            as many CVEs as a year earlier.
            {kg && (
              <>
                {' '}
                CISA KEV additions in the same months: <strong class="sh__kev">{kg.ratio.toFixed(1)}×</strong>, {fmtInt(kg.now)} against {fmtInt(kg.before)}.
              </>
            )}
          </p>
          <Spark stats={stats} g={g} />
          <p class="sh__axis mono" aria-hidden="true">
            <span>{fmtMonth(shiftMonth(last.month, 1 - Math.min(SPARK_MONTHS, m.length)))}</span>
            <span>{fmtMonth(last.month)}</span>
          </p>
        </div>
      )}
      <ul class="tiles sh__tiles">
        {tiles.map((t) => (
          <li key={t.label} class="tile">
            <span class="tile__label">{t.label}</span>
            <span class="tile__value">
              <Num value={t.value} format={t.format} />
            </span>
            <span class="tile__note">{t.note}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

const CNA_TOP = 10;
const AI_TOP = 10;

export default function Surge() {
  useTitle('The Surge');
  const stats = useData(data.stats);
  const meta = useData(data.meta);
  const cnas = useMemo(() => (stats.status === 'ready' ? stats.data.cnas : []), [stats]);
  const maxCna = Math.max(1, ...cnas.map((c) => c.count));
  const lede = useMemo(() => (stats.status === 'ready' ? ledeText(growth(stats.data.monthly, stats.data.generated_at)) : LEDE_FALLBACK), [stats]);
  const k = useStore(knob);
  // The day counts in stats.json are at the default bar; the signal rows re-tier them at the viewer's.
  // Both files are already cached when the visitor came from Today; kev.json is about 35 KB.
  const signal = useData(stats.status === 'ready' ? data.signal : null);
  const kev = useData(stats.status === 'ready' ? data.kev : null);
  // Only The Surge reads surge.json (about 18 KB gzip). Older data has none: the chart then hides its filters.
  const surge = useData(stats.status === 'ready' ? data.surge : null);
  const daily = useMemo<readonly DayRow[]>(() => {
    if (stats.status !== 'ready') return [];
    return signal.status === 'ready' ? dailyAt(stats.data.daily, signal.data, k) : stats.data.daily;
  }, [stats, signal, k]);
  const kevDays = useMemo(() => (kev.status === 'ready' ? kevByDay(kev.data.entries) : new Map<string, number>()), [kev]);
  const partialDay = stats.status === 'ready' && lastDayPartial(stats.data.daily, stats.data.generated_at);
  const takeaway = useMemo(() => dailyTakeaway(daily, partialDay), [daily, partialDay]);
  const lagYears = useMemo(() => (stats.status === 'ready' ? chartYears(stats.data.kev_lag) : []), [stats]);
  const risk = useMemo(() => (stats.status === 'ready' ? riskRows(stats.data.monthly, stats.data.generated_at) : []), [stats]);
  const maxAi = stats.status === 'ready' ? Math.max(1, ...stats.data.ai_credits.map((a) => a.count)) : 1;
  const [allCnas, setAllCnas] = useState(false);
  const [allAi, setAllAi] = useState(false);
  return (
    <div class="page page--surge">
      <header class="page__head">
        <p class="eyebrow">CVE volume since 1999</p>
        <h1 class="page__title" tabIndex={-1}>
          The Surge
        </h1>
        <p class="page__lede">{lede}</p>
      </header>
      {stats.status === 'error' ? (
        <ErrorState error={stats.error} onRetry={stats.retry} />
      ) : stats.status !== 'ready' ? (
        <Loading label="Loading statistics" lines={4} height="80px" />
      ) : (
        <>
          <Hero stats={stats.data} ytd={meta.status === 'ready' ? meta.data.counts.published_ytd : stats.data.monthly.filter((m) => m.month.startsWith(stats.data.monthly[stats.data.monthly.length - 1].month.slice(0, 4))).reduce((a, m) => a + m.published, 0)} />
          <Section n="01" kicker="The flood" id="monthly-h" title="CVEs per month" sub="By datePublished (or dateReserved). The figures above always count every CVE; the line under the chart follows your range and filters.">
            <MonthlyChart monthly={stats.data.monthly} generatedAt={stats.data.generated_at} surge={surge.status === 'ready' ? surge.data : surge.status === 'error' ? 'missing' : null} />
          </Section>
          {risk.length > 1 && (
            <Section n="02" kicker="Volume is not risk" id="risk-h" title="CISA KEV additions per 1,000 new CVEs" sub="Per year: CVEs published, and CVEs of any age CISA added to KEV, on the same scale. Since 2023, as KEV opened in late 2021 with a backlog of old CVEs.">
              <RiskGap rows={risk} />
            </Section>
          )}
          {lagYears.length > 0 && (
            <Section
              n="03"
              kicker="How fast CISA lists"
              id="lag-h"
              title="Time to KEV"
              sub={
                <>
                  Days from a CVE’s publication to its CISA KEV listing, by the year CISA listed it. Grouped by year listed, so every year is complete: grouped by year published, recent years look faster only
                  because their late listings have not happened yet. KEV lists exploitation CISA can confirm, often after it starts. 2021 and 2022 are left out for KEV’s opening backlog;{' '}
                  <a href={href('feeds')}>stats.json</a> has them.
                </>
              }
            >
              <KevLagChart years={lagYears} />
            </Section>
          )}
          <Section n="04" kicker="Right now" id="daily-h" title="The last 30 days" sub={`Grey is every CVE published that day; lit is what cleared your evidence bar (${k}). Square-root scale, so the few stay visible.`}>
            <figure class="chart">
              <DailyChart days={daily} kev={kevDays} kevReady={kev.status === 'ready'} partialLast={partialDay} knob={k} />
              {takeaway && <figcaption class="chart__take">{takeaway}</figcaption>}
              <DailyTable days={daily} kev={kevDays} kevReady={kev.status === 'ready'} partialLast={partialDay} />
            </figure>
          </Section>
          <div class="surge__grid">
            <Section n="05" kicker="Who files it" id="cna-h" title="Who publishes the window" aside={<span class="panel__sub">top {cnas.length} CNAs</span>}>
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
                    {(allCnas ? cnas : cnas.slice(0, CNA_TOP)).map((c, i) => (
                      <tr key={c.cna} style={{ '--i': i }}>
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
              {cnas.length > CNA_TOP && (
                <button type="button" class="btn btn--sm btn--ghost sect__more" aria-expanded={allCnas ? 'true' : 'false'} onClick={() => setAllCnas(!allCnas)}>
                  {allCnas ? `Show the top ${CNA_TOP}` : `Show all ${cnas.length}`}
                </button>
              )}
            </Section>
            <Section
              n="06"
              kicker="Found with AI"
              id="ai-h"
              title="AI-credited discoveries"
              aside={<span class="panel__sub">{meta.status === 'ready' ? `${fmtInt(meta.data.counts.ai_credited_window)} in the window` : ''}</span>}
              sub="Credits that name an AI system or lab. Information only: AI-found bugs are exploited at about the base rate."
            >
              <ol class="ranklist ranklist--bars">
                {(allAi ? stats.data.ai_credits : stats.data.ai_credits.slice(0, AI_TOP)).map((a, i) => (
                  <li key={a.text} style={{ '--w': `${(a.count / maxAi) * 100}%`, '--i': i }}>
                    <span class="ranklist__text">“{a.text}”</span>
                    <span class="mono">{fmtInt(a.count)}</span>
                  </li>
                ))}
              </ol>
              {stats.data.ai_credits.length > AI_TOP && (
                <button type="button" class="btn btn--sm btn--ghost sect__more" aria-expanded={allAi ? 'true' : 'false'} onClick={() => setAllAi(!allAi)}>
                  {allAi ? `Show the top ${AI_TOP}` : `Show all ${stats.data.ai_credits.length}`}
                </button>
              )}
            </Section>
          </div>
        </>
      )}
    </div>
  );
}
