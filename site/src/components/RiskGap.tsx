/**
 * Volume is not risk: per year since 2023, the CVEs published (grey) and the CISA KEV additions
 * (red) on the same scale, with KEV additions per 1,000 new CVEs. The red bars are short on
 * purpose: that is the point. Bars grow in when the section scrolls into view (CSS, under
 * .is-armed / .is-in); the table below has every number.
 */
import { fmtInt } from '../format';
import { riskTakeaway, type RiskRow } from '../surge';

export function RiskGap({ rows }: { rows: readonly RiskRow[] }) {
  const max = Math.max(1, ...rows.map((r) => r.published));
  const take = riskTakeaway(rows);
  return (
    <figure class="chart gap">
      <ul class="legend legend--inline gap__legend" aria-hidden="true">
        <li class="legend__item">
          <span class="gap__key" />
          CVEs published
        </li>
        <li class="legend__item">
          <span class="gap__key gap__key--kev" />
          Added to CISA KEV
        </li>
      </ul>
      <ol class="gap__rows">
        {rows.map((r, i) => (
          <li key={r.year} class="gap__row" style={{ '--i': i }}>
            <span class="sr-only">{`${r.year}${r.partial ? ' so far' : ''}: ${fmtInt(r.published)} CVEs published, ${fmtInt(r.kev)} added to CISA KEV, ${r.perThousand.toFixed(1)} per 1,000.`}</span>
            <span class="gap__year mono" aria-hidden="true">
              {r.year}
              {r.partial && <span class="muted"> so far</span>}
            </span>
            <span class="gap__bars" aria-hidden="true">
              <span class="gap__track" style={{ '--w': `${(r.published / max) * 100}%` }}>
                <span class="gap__bar" />
                <span class="gap__val mono">{fmtInt(r.published)}</span>
              </span>
              <span class="gap__track gap__track--kev" style={{ '--w': `max(3px, ${(r.kev / max) * 100}%)` }}>
                <span class="gap__bar gap__bar--kev" />
                <span class="gap__val gap__val--kev mono">{fmtInt(r.kev)}</span>
              </span>
            </span>
            <span class="gap__rate" aria-hidden="true">
              <span class="gap__num mono">{r.perThousand.toFixed(1)}</span>
              <span class="gap__unit">per 1,000</span>
            </span>
          </li>
        ))}
      </ol>
      {take && <figcaption class="chart__take">{take}</figcaption>}
      <details class="chart__table">
        <summary>View as table</summary>
        <div class="tablewrap">
          <table class="table table--compact">
            <thead>
              <tr>
                <th scope="col">Year</th>
                <th scope="col" class="num">
                  CVEs published
                </th>
                <th scope="col" class="num">
                  Added to KEV
                </th>
                <th scope="col" class="num">
                  Per 1,000 CVEs
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.year}>
                  <th scope="row" class="chart__month">
                    {r.year}
                    {r.partial && <span class="muted"> so far</span>}
                  </th>
                  <td class="num">{fmtInt(r.published)}</td>
                  <td class="num">{fmtInt(r.kev)}</td>
                  <td class="num">{r.perThousand.toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}
