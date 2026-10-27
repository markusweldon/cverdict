import type { KevEntry } from '../../../shared/contract';
import { DAY_MS, fmtCountdown, fmtDate, HOUR_MS, kevDeadline, vendorProduct } from '../format';
import { useNow } from '../hooks';
import { cveHref } from '../router';
import { IconLock, IconScan } from './icons';

export type KevUrgency = 'overdue' | 'soon' | 'later';

export function kevUrgency(e: KevEntry, now: number): KevUrgency {
  const left = kevDeadline(e.due_date) - now;
  return left < 0 ? 'overdue' : left <= 72 * HOUR_MS ? 'soon' : 'later';
}

/** Live countdown to the end of the KEV due date (UTC). */
export function Countdown({ due, class: cls }: { due: string; class?: string }) {
  const now = useNow(1000);
  const left = kevDeadline(due) - now;
  const overdue = left < 0;
  return (
    <span class={`countdown${overdue ? ' is-overdue' : left <= 72 * HOUR_MS ? ' is-soon' : ''}${cls ? ` ${cls}` : ''}`}>
      <span class="countdown__label">{overdue ? 'overdue' : 'due in'}</span>
      <span class="countdown__time" role="timer" aria-live="off">
        {fmtCountdown(left)}
      </span>
    </span>
  );
}

export function KevFlags({ e }: { e: Pick<KevEntry, 'ransomware' | 'forensic_triage'> }) {
  return (
    <span class="kevflags">
      {e.ransomware === 'Known' && (
        <span class="kevflag kevflag--ransom" data-tip="CISA: known use in ransomware campaigns">
          <IconLock size={12} /> Ransomware
        </span>
      )}
      {e.forensic_triage && (
        <span class="kevflag kevflag--forensic" data-tip="CISA asks for forensic triage, not just patching (BOD 26-04)">
          <IconScan size={12} /> Forensic triage
        </span>
      )}
    </span>
  );
}

/** Upcoming deadlines (soonest first), then the ones missed in the last `overdueDays` (latest first). */
export function upcomingKev(entries: readonly KevEntry[], now: number, overdueDays = 7): KevEntry[] {
  const byDue = (a: KevEntry, b: KevEntry) => a.due_date.localeCompare(b.due_date) || a.id.localeCompare(b.id);
  const upcoming = entries.filter((e) => kevDeadline(e.due_date) >= now).sort(byDue);
  const overdue = entries.filter((e) => kevDeadline(e.due_date) < now && kevDeadline(e.due_date) - now > -overdueDays * DAY_MS).sort((a, b) => byDue(b, a));
  return [...upcoming, ...overdue];
}

/** The nearest KEV deadlines, for the Today page. */
export function KevStrip({ entries, limit }: { entries: readonly KevEntry[]; limit: number }) {
  const now = useNow(60_000);
  const list = upcomingKev(entries, now).slice(0, limit);
  return (
    <ol class="kevstrip">
      {list.map((e) => (
        <li key={e.id} class={`kevcard kevcard--${kevUrgency(e, now)}`}>
          <a class="kevcard__link" href={cveHref(e.id)}>
            <Countdown due={e.due_date} />
            <span class="kevcard__id">{e.id}</span>
            <span class="kevcard__who">{vendorProduct(e.vendor, e.product)}</span>
            <span class="kevcard__due">
              due {fmtDate(e.due_date)} · added {fmtDate(e.date_added)}
            </span>
          </a>
          <KevFlags e={e} />
        </li>
      ))}
    </ol>
  );
}
