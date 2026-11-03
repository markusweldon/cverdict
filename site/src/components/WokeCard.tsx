/** Today's side card: how many old CVEs woke up in the last 7 days, and the most urgent of them. */
import { data } from '../data';
import { tierAt } from '../filters';
import { fmtDate, fmtInt, plural, vendorProduct } from '../format';
import { useData } from '../hooks';
import { cveHref, href } from '../router';
import { mostUrgent, wokeWithin } from '../woke';
import { IconArrowRight } from './icons';
import { TierPill } from './Tier';

const WEEK_DAYS = 7;
const SHOWN = 4;

export function WokeCard({ level }: { level: number }) {
  const woke = useData(data.woke);
  // Optional: data published before this feature has no woke.json, and the card simply stays away.
  if (woke.status !== 'ready') return null;
  const generated = Date.parse(woke.data.generated_at);
  const week = wokeWithin(woke.data.items, generated, WEEK_DAYS);
  const top = mostUrgent(week, (i) => tierAt(i.row, level)).slice(0, SHOWN);
  const total = woke.data.items.length;
  return (
    <section class="panel wokecard" aria-labelledby="woke-h">
      <header class="panel__head">
        <h2 id="woke-h" class="panel__title">
          Woke up
        </h2>
        <a class="section__more" href={href('woke')} aria-label={`All ${fmtInt(total)} old ${total === 1 ? 'CVE' : 'CVEs'} that woke up`}>
          All {fmtInt(total)} <IconArrowRight size={12} />
        </a>
      </header>
      <p class="wokecard__lede">
        {week.length > 0 ? (
          <>
            <strong>{plural(week.length, 'old CVE')}</strong> gained exploitation evidence in the last 7 days.
          </>
        ) : (
          <>No old CVE gained exploitation evidence in the last 7 days{total > 0 ? `; ${fmtInt(total)} did in the last ${woke.data.days} days` : ''}.</>
        )}
      </p>
      {top.length > 0 && (
        <ol class="changes__list">
          {top.map((it) => {
            const newest = it.signals[it.signals.length - 1];
            return (
              <li key={it.id} class="change">
                <a class="change__link" href={cveHref(it.id)}>
                  <span class="change__id">{it.id}</span>
                  <span class="change__who">{vendorProduct(it.row.v, it.row.p)}</span>
                </a>
                <span class="change__tiers">
                  <TierPill tier={tierAt(it.row, level)} size="sm" />
                </span>
                <span class="wokecard__why">
                  {fmtDate(newest.at)}: {newest.label}
                </span>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
