/** Woke-up signals: the dated evidence that brought an old CVE back. */
import type { WakeSignal } from '../../../shared/contract';
import { fmtDate } from '../format';
import { firstSeenTip } from '../woke';
import { ExtLink } from './ExtLink';

/** One line per signal, oldest first: "Oct 30 · added to CISA KEV ↗". */
export function WakeSignals({ signals, class: cls }: { signals: readonly WakeSignal[]; class?: string }) {
  return (
    <ul class={`wakes${cls ? ` ${cls}` : ''}`} aria-label="Why it woke up">
      {signals.map((s) => (
        <li key={`${s.kind}-${s.at}`} class={`wake wake--${s.kind}`}>
          <time class="wake__at" dateTime={s.at}>
            {fmtDate(s.at)}
          </time>
          {s.url ? (
            <ExtLink href={s.url} class="wake__label">
              {s.label}
            </ExtLink>
          ) : (
            <span class="wake__label">{s.label}</span>
          )}
          {s.first_seen && (
            <span class="wake__seen" data-tip={firstSeenTip(s)}>
              date first seen
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}
