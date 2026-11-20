/** The Surge: CVE volume since 1999, the window day by day, and who publishes it. */
import { useMemo } from 'preact/hooks';
import type { StatsFile } from '../../../shared/contract';
import { DailyChart } from '../components/DailyChart';
import { MonthlyChart } from '../components/MonthlyChart';
import { ErrorState, Loading } from '../components/States';
import { data } from '../data';
import { dailyAt, dailyTakeaway, kevByDay, lastDayPartial, type DayRow } from '../daily';
import { cnaName, fmtInt, fmtMonth, fmtPct } from '../format';
import { useData, useTitle } from '../hooks';
import { href } from '../router';
import { knob, useStore } from '../state';
import { LEDE_FALLBACK, busiestComplete, growth, ledeText } from '../surge';

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

function Tiles({ stats, ytd }: { stats: StatsFile; ytd: number }) {
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
  return (
    <div class="page page--surge">
      <header class="page__head">
        <p class="eyebrow">Volume since 1999</p>
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
          <Tiles stats={stats.data} ytd={meta.status === 'ready' ? meta.data.counts.published_ytd : stats.data.monthly.filter((m) => m.month.startsWith(stats.data.monthly[stats.data.monthly.length - 1].month.slice(0, 4))).reduce((a, m) => a + m.published, 0)} />
          <section class="panel" aria-labelledby="monthly-h">
            <header class="panel__head">
              <div>
                <h2 id="monthly-h" class="panel__title">
                  CVEs per month
                </h2>
                <p class="panel__sub">By datePublished (or dateReserved). The lede and tiles above always count every CVE; the line under the chart follows your range and filters.</p>
              </div>
            </header>
            <MonthlyChart monthly={stats.data.monthly} generatedAt={stats.data.generated_at} surge={surge.status === 'ready' ? surge.data : surge.status === 'error' ? 'missing' : null} />
          </section>
          <section class="panel" aria-labelledby="daily-h">
            <header class="panel__head">
              <div>
                <h2 id="daily-h" class="panel__title">
                  The last 30 days
                </h2>
                <p class="panel__sub">Grey is every CVE published that day; lit is what cleared your evidence bar ({k}). Square-root scale, so the few stay visible.</p>
              </div>
            </header>
            <figure class="chart">
              <DailyChart days={daily} kev={kevDays} kevReady={kev.status === 'ready'} partialLast={partialDay} knob={k} />
              {takeaway && <figcaption class="chart__take">{takeaway}</figcaption>}
              <DailyTable days={daily} kev={kevDays} kevReady={kev.status === 'ready'} partialLast={partialDay} />
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
