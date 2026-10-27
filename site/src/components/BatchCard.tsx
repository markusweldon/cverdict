import type { Batch, Row, Tier } from '../../../shared/contract';
import type { TierCounts } from '../filters';
import { cnaName, fmtDate, fmtInt, plural, vendorProduct } from '../format';
import { cveHref, href } from '../router';
import { TIER_META } from '../tiers';
import { TierBar, TierPill } from './Tier';

/** "Microsoft · Oct 13 · 1,407 → 3 exploited · 19 likely · 2 PoC". */
export function batchSummary(counts: TierCounts, pocs: number): string {
  const parts: string[] = [];
  if (counts.exploited) parts.push(`${fmtInt(counts.exploited)} exploited`);
  if (counts.likely) parts.push(`${fmtInt(counts.likely)} likely`);
  if (pocs) parts.push(plural(pocs, 'PoC'));
  return parts.length > 0 ? parts.join(' · ') : 'nothing passed';
}

interface Props {
  batch: Batch;
  counts: TierCounts;
  pocs: number;
  topTier: (r: Row) => Tier;
  compact?: boolean;
  expanded?: boolean;
  onToggle?: () => void;
}

export function BatchCard({ batch, counts, pocs, topTier, compact, expanded, onToggle }: Props) {
  const passed = counts.exploited + counts.likely;
  const best = batch.top[0];
  const lead: Tier = counts.exploited ? 'exploited' : counts.likely ? 'likely' : 'quiet';
  return (
    <article class={`batch batch--${lead}${expanded ? ' is-open' : ''}`} id={compact ? undefined : batch.id}>
      <header class="batch__head">
        <h3 class="batch__title">
          <a href={href(`batches#${batch.id}`)}>{cnaName(batch.cna)}</a>
        </h3>
        <span class="batch__date">{fmtDate(batch.date)}</span>
      </header>
      <div class="batch__count">
        <span class="batch__num">{fmtInt(batch.count)}</span>
        <span class="batch__arrow" aria-hidden="true">→</span>
        <span class={`batch__passed${passed ? ' is-lit' : ''}`}>{fmtInt(passed)}</span>
        <span class="batch__unit">passed</span>
      </div>
      <TierBar counts={counts} label={`${batch.count} CVEs: ${(['exploited', 'likely', 'watch', 'quiet'] as const).map((t) => `${counts[t]} ${TIER_META[t].label.toLowerCase()}`).join(', ')}`} />
      <p class="batch__summary">{batchSummary(counts, pocs)}</p>
      {!expanded && batch.families.length > 0 && (
        <p class="batch__families">
          {batch.families.slice(0, 3).map((f, i) => (
            <span key={f.name}>
              {i > 0 && <span class="sep"> · </span>}
              {f.name} <span class="mono muted">{fmtInt(f.count)}</span>
            </span>
          ))}
        </p>
      )}
      {!expanded && best && (
        <a class="batch__top" href={cveHref(best.id)}>
          <TierPill tier={topTier(best)} size="sm" />
          <span class="mono">{best.id}</span>
          <span class="batch__top-who">{vendorProduct(best.v, best.p)}</span>
        </a>
      )}
      {expanded && (
        <div class="batch__detail">
          <table class="table table--compact">
            <caption class="sr-only">Most common products in this batch</caption>
            <thead>
              <tr>
                <th scope="col">Product family</th>
                <th scope="col" class="num">CVEs</th>
                <th scope="col" class="num">Passed</th>
              </tr>
            </thead>
            <tbody>
              {batch.families.map((f) => (
                <tr key={f.name}>
                  <td>{f.name}</td>
                  <td class="num">{fmtInt(f.count)}</td>
                  <td class={`num${f.passed ? ' is-lit' : ''}`}>{fmtInt(f.passed)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h4 class="batch__sub">Top CVEs</h4>
          <ul class="batch__tops">
            {batch.top.map((r) => (
              <li key={r.id}>
                <a href={cveHref(r.id)}>
                  <TierPill tier={topTier(r)} size="sm" />
                  <span class="mono">{r.id}</span>
                  <span class="mono muted">{r.s}</span>
                  <span class="batch__top-title">{r.t}</span>
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
      {onToggle && (
        <button type="button" class="batch__toggle btn btn--ghost btn--sm" aria-expanded={expanded ? 'true' : 'false'} onClick={onToggle}>
          {expanded ? 'Collapse' : 'Families & top CVEs'}
        </button>
      )}
    </article>
  );
}
