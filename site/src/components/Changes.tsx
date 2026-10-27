import type { Change, Row } from '../../../shared/contract';
import { fmtAge, plural, vendorProduct } from '../format';
import { useNow } from '../hooks';
import { cveHref } from '../router';
import { previousVisit } from '../state';
import { Chip } from './Chip';
import { IconArrowRight } from './icons';
import { TierPill } from './Tier';
import { EmptyState } from './States';

/** Escalations from the last pipeline runs: tier rose, or a new exploitation/exploit chip appeared. */
export function Changes({ items, rows, limit = 8 }: { items: readonly Change[]; rows: ReadonlyMap<string, Row>; limit?: number }) {
  const now = useNow(60_000);
  const since = previousVisit;
  const fresh = since === null ? 0 : items.filter((c) => Date.parse(c.at) > since).length;
  if (items.length === 0) return <EmptyState title="No escalations this week">Nothing moved up a tier in the last 7 days.</EmptyState>;
  return (
    <div class="changes">
      {fresh > 0 && (
        <p class="changes__since">
          <span class="dot dot--accent" aria-hidden="true" />
          {plural(fresh, 'escalation')} since your last visit ({fmtAge(new Date(previousVisit!).toISOString(), now)} ago)
        </p>
      )}
      <ol class="changes__list">
        {items.slice(0, limit).map((c) => {
          const row = rows.get(c.id);
          const isNew = previousVisit !== null && Date.parse(c.at) > previousVisit;
          return (
            <li key={`${c.id}-${c.at}`} class={`change${isNew ? ' is-new' : ''}`}>
              <a class="change__link" href={cveHref(c.id)}>
                <span class="change__id">{c.id}</span>
                <span class="change__who">{row ? vendorProduct(row.v, row.p) : ''}</span>
              </a>
              <span class="change__tiers">
                {c.from ? <TierPill tier={c.from} size="sm" /> : <span class="change__new">new</span>}
                <IconArrowRight size={12} />
                <TierPill tier={c.to} size="sm" />
              </span>
              <span class="change__chips">
                {c.added.slice(0, 2).map((id) => (
                  <Chip key={id} id={id} />
                ))}
              </span>
              <time class="change__at" dateTime={c.at}>
                {fmtAge(c.at, now)}
              </time>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
