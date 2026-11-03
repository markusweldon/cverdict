/** KEV Clock: CISA Known Exploited Vulnerabilities deadlines with live countdowns. */
import type { KevEntry } from '../../../shared/contract';
import { copyLink } from '../actions';
import { IconCalendar, IconCopy, IconRss } from '../components/icons';
import { Countdown, KevFlags } from '../components/Kev';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { data, FEEDS_BASE } from '../data';
import { DAY_MS, fmtCountdown, fmtDate, fmtInt, HOUR_MS, kevDeadline, plural, vendorProduct } from '../format';
import { useData, useNow, useTitle } from '../hooks';
import { cveHref } from '../router';

interface Group {
  id: string;
  title: string;
  blurb: string;
  entries: KevEntry[];
}

function groups(entries: readonly KevEntry[], now: number): Group[] {
  const d = new Date(now);
  const monthEnd = Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
  const soon: KevEntry[] = [];
  const overdue: KevEntry[] = [];
  const month: KevEntry[] = [];
  const later: KevEntry[] = [];
  for (const e of entries) {
    const left = kevDeadline(e.due_date) - now;
    if (left < -7 * DAY_MS) continue;
    if (left < 0) overdue.push(e);
    else if (left <= 72 * HOUR_MS) soon.push(e);
    else if (kevDeadline(e.due_date) <= monthEnd) month.push(e);
    else later.push(e);
  }
  const byDue = (a: KevEntry, b: KevEntry) => a.due_date.localeCompare(b.due_date) || a.id.localeCompare(b.id);
  return [
    { id: 'soon', title: 'Due within 72 hours', blurb: 'Federal agencies must remediate by the end of the due date.', entries: soon.sort(byDue) },
    { id: 'overdue', title: 'Overdue · last 7 days', blurb: 'Deadlines that passed in the last week.', entries: overdue.sort(byDue).reverse() },
    { id: 'month', title: 'Due this month', blurb: 'Later deadlines before the month ends.', entries: month.sort(byDue) },
    { id: 'later', title: 'Due later', blurb: 'Added recently with longer deadlines.', entries: later.sort(byDue) },
  ];
}

function KevRow({ e }: { e: KevEntry }) {
  return (
    <li class="kevrow">
      <Countdown due={e.due_date} class="kevrow__clock" />
      <div class="kevrow__main">
        <a class="kevrow__id" href={cveHref(e.id)}>
          {e.id}
        </a>
        <span class="kevrow__who">{vendorProduct(e.vendor, e.product)}</span>
        <p class="kevrow__name">{e.name}</p>
        <KevFlags e={e} />
      </div>
      <dl class="kevrow__dates">
        <div>
          <dt>Added</dt>
          <dd>{fmtDate(e.date_added)}</dd>
        </div>
        <div>
          <dt>Due</dt>
          <dd>{fmtDate(e.due_date)}</dd>
        </div>
        <div>
          <dt>Score</dt>
          <dd class="mono">{e.score ?? '—'}</dd>
        </div>
      </dl>
    </li>
  );
}

export default function Kev() {
  useTitle('KEV Clock');
  const kev = useData(data.kev);
  const now = useNow(1000);
  const ics = new URL(`${FEEDS_BASE}kev-due.ics`, window.location.origin).href;
  const atom = new URL(`${FEEDS_BASE}kev.xml`, window.location.origin).href;
  return (
    <div class="page">
      <header class="page__head">
        <p class="eyebrow">CISA Known Exploited Vulnerabilities</p>
        <h1 class="page__title" tabIndex={-1}>
          KEV Clock
        </h1>
        <p class="page__lede">Confirmed exploitation with a federal deadline. Listing usually lags the first attacks — not in KEV ≠ not exploited.</p>
        <div class="page__actions">
          <a class="btn" href={ics}>
            <IconCalendar size={14} /> Subscribe (.ics)
          </a>
          <button type="button" class="btn btn--ghost" onClick={() => void copyLink(ics, 'Calendar URL')}>
            <IconCopy size={14} /> Copy calendar URL
          </button>
          <a class="btn btn--ghost" href={atom}>
            <IconRss size={14} /> Atom feed
          </a>
        </div>
      </header>
      {kev.status === 'error' ? (
        <ErrorState error={kev.error} onRetry={kev.retry} />
      ) : kev.status !== 'ready' ? (
        <Loading label="Loading KEV deadlines" lines={6} height="52px" />
      ) : (
        (() => {
          const gs = groups(kev.data.entries, now);
          const next = gs[0].entries[0] ?? gs[2].entries[0] ?? gs[3].entries[0];
          const added30 = kev.data.entries.filter((e) => Date.parse(e.date_added) >= now - 30 * DAY_MS).length;
          return (
            <>
              <section class="kevhero" aria-label="Next deadline">
                {next ? (
                  <>
                    <p class="eyebrow">Next deadline</p>
                    <p class="kevhero__clock mono" role="timer">
                      {fmtCountdown(kevDeadline(next.due_date) - now, true)}
                    </p>
                    <p class="kevhero__what">
                      <a href={cveHref(next.id)} class="mono">
                        {next.id}
                      </a>{' '}
                      · {vendorProduct(next.vendor, next.product)} · due {fmtDate(next.due_date)}
                    </p>
                  </>
                ) : (
                  <p class="kevhero__what">No upcoming deadlines in the catalog slice we keep.</p>
                )}
                <dl class="kevhero__stats">
                  <div>
                    <dt>Due ≤ 72h</dt>
                    <dd>{fmtInt(gs[0].entries.length)}</dd>
                  </div>
                  <div>
                    <dt>Overdue (7d)</dt>
                    <dd>{fmtInt(gs[1].entries.length)}</dd>
                  </div>
                  <div>
                    <dt>Added in 30 days</dt>
                    <dd>{fmtInt(added30)}</dd>
                  </div>
                  <div>
                    <dt>Ransomware</dt>
                    <dd>{fmtInt(kev.data.entries.filter((e) => e.ransomware === 'Known').length)}</dd>
                  </div>
                </dl>
              </section>
              {gs.map((g) => (
                <section key={g.id} class={`kevgroup kevgroup--${g.id}`} aria-labelledby={`kg-${g.id}`}>
                  <header class="section__head">
                    <h2 class="section__title" id={`kg-${g.id}`}>
                      {g.title} <span class="section__count">{plural(g.entries.length, 'CVE')}</span>
                    </h2>
                    <p class="section__sub">{g.blurb}</p>
                  </header>
                  {g.entries.length ? (
                    <ol class="kevlist">
                      {g.entries.map((e) => (
                        <KevRow key={e.id} e={e} />
                      ))}
                    </ol>
                  ) : (
                    <EmptyState title="Nothing here right now" />
                  )}
                </section>
              ))}
              <p class="fineprint">
                Catalog version {kev.data.catalog_version ?? 'unknown'}. Deadlines are counted to the end of the due date, UTC. This page keeps entries added in the last 30 days or due from 14 days ago.
              </p>
            </>
          );
        })()
      )}
    </div>
  );
}
