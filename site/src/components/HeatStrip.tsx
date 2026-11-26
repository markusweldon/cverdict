/** Today's Heating up strip: the few CVEs with the most new exploitation evidence this week (site/src/heat.ts). */
import { fmtAge, vendorProduct } from '../format';
import { HEAT_DAYS, HEAT_LABEL, type HeatCard } from '../heat';
import { useNow } from '../hooks';
import { cveHref } from '../router';
import { TierPill } from './Tier';

export function HeatStrip({ cards }: { cards: readonly HeatCard[] }) {
  const now = useNow(60_000);
  if (cards.length < 2) return null;
  return (
    <section class="panel today__heat heat" aria-labelledby="heat-h">
      <header class="panel__head">
        <div>
          <h2 id="heat-h" class="panel__title">
            Heating up
          </h2>
          <p class="panel__sub">
            The most new exploitation evidence in the last {HEAT_DAYS} days: KEV and catalog listings and vendor reports first, then exploit code. Newer counts more.
          </p>
        </div>
      </header>
      <ol class="heat__list">
        {cards.map((c, i) => (
          <li key={c.cve} class={`heat__card heat__card--${c.tier}`}>
            <a class="heat__link" href={cveHref(c.cve)}>
              <span class="heat__rank mono" aria-hidden="true">
                {i + 1}
              </span>
              <span class="heat__who">{vendorProduct(c.vendor, c.product) || c.cve}</span>
              <span class="heat__id mono">
                {c.cve}
                {c.more.length > 0 && <span class="muted" title={c.more.join(', ')}> +{c.more.length} more</span>}
              </span>
            </a>
            <span class="heat__meta">
              <TierPill tier={c.tier} size="sm" />
              <span class="heat__score">
                <span class="muted">score</span> <span class="mono">{c.score}</span>
              </span>
              <time class="heat__at muted" dateTime={c.latest}>
                {fmtAge(c.latest, now)}
              </time>
            </span>
            <ul class="heat__what" aria-label="New this week">
              {c.what.map((t) => (
                <li key={t} class={`heat__tag heat__tag--${t}`}>
                  {HEAT_LABEL[t]}
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ol>
    </section>
  );
}
