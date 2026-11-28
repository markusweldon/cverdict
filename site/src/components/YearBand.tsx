/**
 * Today's "2026 so far" band: the year's CVEs against the year's newly exploited ones (CISA KEV
 * additions), each against the same days a year earlier, and a counter of days since CISA last
 * listed a CVE as exploited, with the CVE that reset it. The point is the pair: volume went
 * vertical, exploitation did not.
 */
import type { KevEntry, Meta, StatsFile } from '../../../shared/contract';
import { cnaName, fmtDate, fmtInt, fmtPct, vendorProduct } from '../format';
import { useCountUp, useNow } from '../hooks';
import { kevStreak } from '../kevstreak';
import { cveHref, href } from '../router';
import { sameDaysLastYear } from '../surge';

function Num({ value }: { value: number }) {
  return <>{fmtInt(useCountUp(value, 1000))}</>;
}

const change = (now: number, before: number) => (before > 0 ? `${now >= before ? '+' : '−'}${fmtPct(Math.abs(now / before - 1))}` : '');

export function YearBand({ meta, stats, kev }: { meta: Meta; stats: StatsFile | null; kev: readonly KevEntry[] | null }) {
  const now = useNow(60_000);
  const pub = stats ? sameDaysLastYear(stats.monthly, stats.generated_at, (m) => m.published) : null;
  const ex = stats ? sameDaysLastYear(stats.monthly, stats.generated_at, (m) => m.kev_added) : null;
  const year = pub?.year ?? new Date(meta.generated_at).getUTCFullYear();
  const published = meta.counts.published_ytd;
  const streak = kev ? kevStreak(kev, now) : null;
  const top = streak?.resetBy[0];
  return (
    <section class="yearband" aria-label={`${year} so far`}>
      <a class="yearband__item" href={href('surge')}>
        <span class="yearband__label mono">{year} so far</span>
        <span class="yearband__value">
          <Num value={published} />
        </span>
        <span class="yearband__note">CVEs published{pub && pub.before > 0 ? `, ${change(published, pub.before)} on the same days of ${year - 1}` : ''}</span>
      </a>
      <a class="yearband__item yearband__item--hot" href={href('kev')}>
        <span class="yearband__label mono">Newly exploited</span>
        <span class="yearband__value">
          <Num value={ex?.now ?? 0} />
        </span>
        <span class="yearband__note">
          added to CISA KEV{ex && ex.before > 0 ? `, ${change(ex.now, ex.before)} on ${year - 1}` : ''}. {ex && published > 0 ? `${fmtPct(ex.now / published)} of the volume` : ''}
        </span>
      </a>
      {streak && (
        <div class={`yearband__item yearband__item--clock${streak.days === 0 ? ' is-zero' : ''}`}>
          <span class="yearband__label mono">Days since a new KEV listing</span>
          <span class="yearband__value yearband__days">
            <span class="yearband__pulse" aria-hidden="true" />
            {streak.days}
          </span>
          <span class="yearband__note">
            {top ? (
              <>
                Reset by{' '}
                <a class="mono" href={cveHref(top.id)}>
                  {top.id}
                </a>{' '}
                {vendorProduct(top.vendor, top.product) || cnaName(top.vendor)}
                {streak.resetBy.length > 1 ? ` and ${streak.resetBy.length - 1} more` : ''}, {fmtDate(streak.last, Number.NaN)}.
              </>
            ) : null}{' '}
            Longest quiet spell in 30 days: {streak.longestGap} {streak.longestGap === 1 ? 'day' : 'days'}.
          </span>
        </div>
      )}
    </section>
  );
}
