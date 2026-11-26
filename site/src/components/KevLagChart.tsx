/** Time to KEV: one stacked bar per year CISA added CVEs, by days from publication to listing. */
import { KEV_LAG_BUCKETS, type KevLagYear } from '../../../shared/contract';
import { fmtInt, fmtPct } from '../format';
import { KEV_LAG_LABELS, KEV_LAG_SHORT, fmtDays, lagTakeaway, withinWeek } from '../kevlag';

export function KevLagChart({ years }: { years: readonly KevLagYear[] }) {
  const take = lagTakeaway(years);
  return (
    <figure class="chart lag">
      <ul class="legend legend--inline lag__legend" aria-hidden="true">
        {KEV_LAG_BUCKETS.map((b) => (
          <li key={b} class="legend__item">
            <span class={`lag__key lag__seg--${b}`} />
            {KEV_LAG_SHORT[b]}
          </li>
        ))}
      </ul>
      <ol class="lag__rows">
        {years.map((r) => (
          <li
            key={r.year}
            class="lag__row"
            aria-label={`${r.year}${r.partial ? ' so far' : ''}: ${fmtInt(r.count)} CVEs added to KEV. ${KEV_LAG_BUCKETS.map((b, i) => `${KEV_LAG_LABELS[b]}: ${fmtInt(r.buckets[i])}`).join('. ')}. Median ${fmtDays(r.median_days)}.`}
          >
            <span class="lag__year mono" aria-hidden="true">
              {r.year}
              {r.partial && <span class="muted"> so far</span>}
            </span>
            <span class="lag__bar" aria-hidden="true">
              {KEV_LAG_BUCKETS.map((b, i) =>
                r.buckets[i] > 0 ? (
                  <span
                    key={b}
                    class={`lag__seg lag__seg--${b}`}
                    style={{ flexGrow: r.buckets[i] }}
                    data-tip={`${KEV_LAG_LABELS[b]}: ${fmtInt(r.buckets[i])} (${fmtPct(r.buckets[i] / r.count)})`}
                  />
                ) : null,
              )}
            </span>
            <span class="lag__stat mono" aria-hidden="true">
              <span data-tip="Median days from publication to the KEV listing">{fmtDays(r.median_days)}</span>
              <span class="muted" data-tip="Listed on the day of publication or within 7 days">
                {fmtPct(withinWeek(r) / r.count)} ≤ 7d
              </span>
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
                <th scope="col">Year added</th>
                <th scope="col" class="num">
                  CVEs
                </th>
                {KEV_LAG_BUCKETS.map((b) => (
                  <th key={b} scope="col" class="num">
                    {KEV_LAG_SHORT[b]}
                  </th>
                ))}
                <th scope="col" class="num">
                  Median
                </th>
              </tr>
            </thead>
            <tbody>
              {[...years].reverse().map((r) => (
                <tr key={r.year}>
                  <th scope="row" class="chart__month">
                    {r.year}
                    {r.partial && <span class="muted"> so far</span>}
                  </th>
                  <td class="num">{fmtInt(r.count)}</td>
                  {r.buckets.map((n, i) => (
                    <td key={KEV_LAG_BUCKETS[i]} class="num">
                      {fmtInt(n)}
                    </td>
                  ))}
                  <td class="num">{fmtDays(r.median_days)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </figure>
  );
}
