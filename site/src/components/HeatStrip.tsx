/**
 * Today's Heating up strip: the few CVEs with the most new exploitation evidence this week
 * (site/src/heat.ts). Each card has a 7-day strip of its evidence, one glowing tick per event in
 * the waterfall's style (red for exploitation reports, orange for exploit code), and a heat meter
 * against the hottest card. Once on screen the cards rise, the ticks light up day by day and the
 * meters fill; reduced motion shows it all at once.
 */
import type { EventType } from '../../../shared/contract';
import { fmtAge, vendorProduct } from '../format';
import { HEAT_DAYS, HEAT_LABEL, type HeatCard } from '../heat';
import { useNow, useReveal } from '../hooks';
import { cveHref } from '../router';
import { TierPill } from './Tier';
import { IconFlame } from './icons';

/** Exploitation reports glow red, working exploit code orange, a tier change grey. */
const KIND: Readonly<Record<EventType, 'hot' | 'code' | 'tier'>> = {
  kev_added: 'hot',
  catalog_listed: 'hot',
  vendor_exploited: 'hot',
  metasploit_module: 'code',
  exploitdb_entry: 'code',
  nuclei_template: 'code',
  tier_up: 'tier',
  fast_lane: 'tier',
};

function Strip({ timeline }: { timeline: HeatCard['timeline'] }) {
  const days = Array.from({ length: HEAT_DAYS }, (_, d) => timeline.filter((t) => t.day === d));
  return (
    <div class="heat__strip" aria-hidden="true">
      <div class="heat__days">
        {days.map((ev, d) => (
          <span key={d} class={`heat__day${d === HEAT_DAYS - 1 ? ' heat__day--today' : ''}`} style={{ '--d': d }}>
            {ev.slice(0, 6).map((t, k) => (
              <i key={k} class={`heat__tick heat__tick--${KIND[t.type]}`} />
            ))}
          </span>
        ))}
      </div>
      <span class="heat__axis mono">
        <span>{HEAT_DAYS}d ago</span>
        <span>now</span>
      </span>
    </div>
  );
}

export function HeatStrip({ cards }: { cards: readonly HeatCard[] }) {
  const now = useNow(60_000);
  const ref = useReveal<HTMLElement>([cards.length >= 2]);
  if (cards.length < 2) return null;
  const top = Math.max(...cards.map((c) => c.heat), 1);
  return (
    <section class="panel today__heat heat" aria-labelledby="heat-h" ref={ref}>
      <header class="panel__head heat__head">
        <div>
          <h2 id="heat-h" class="panel__title heat__title">
            <span class="heat__flame" aria-hidden="true">
              <IconFlame size={16} />
            </span>
            Heating up
            <span class="heat__live mono">last {HEAT_DAYS} days</span>
          </h2>
          <p class="panel__sub">The most new exploitation evidence: KEV and catalog listings and vendor reports first, then exploit code. Newer counts more.</p>
        </div>
        <span class="heat__key mono" aria-hidden="true">
          <span>
            <i class="heat__tick heat__tick--hot" /> exploited
          </span>
          <span>
            <i class="heat__tick heat__tick--code" /> exploit code
          </span>
          <span>
            <i class="heat__tick heat__tick--tier" /> tier up
          </span>
        </span>
      </header>
      <ol class="heat__list">
        {cards.map((c, i) => (
          <li key={c.cve} class={`heat__card heat__card--${c.tier}`} style={{ '--i': i, '--heat': `${Math.max(6, (c.heat / top) * 100)}%` }}>
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
            <Strip timeline={c.timeline} />
            <span class="heat__meter" aria-hidden="true">
              <span class="heat__fill" />
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
