/** Woke up: CVEs published before the 30-day window that gained exploitation evidence in it. */
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { WAKE_KINDS, type WakeKind, type WokeFile } from '../../../shared/contract';
import { copyTicket, watchVendorOf, copyLink } from '../actions';
import { IconCode, IconCopy, IconRss } from '../components/icons';
import { CveRow } from '../components/Row';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { WakeSignals } from '../components/Woke';
import { DataError, data, DATA_BASE, FEEDS_BASE } from '../data';
import { tierAt } from '../filters';
import { fmtDate, fmtDateTime, fmtInt, plural } from '../format';
import { useData, useKnobUrl, useListController, useNow, useTitle } from '../hooks';
import { cveHref, navigate, setQuery, useLocation } from '../router';
import { knob, useStore } from '../state';
import { byKind, byWeek, isWakeKind, listing, trackingNote, WAKE_KIND_LABEL } from '../woke';

function Notes({ woke }: { woke: WokeFile }) {
  const t = trackingNote(woke.tracking);
  const skipped = woke.skipped;
  return (
    <div class="wokenotes">
      {t.since && (
        <p>
          {listing(t.tracked)} have no date at the source, so we date them by the hourly run that first saw them. Tracking since <strong>{fmtDateTime(t.since)}</strong>; whatever was already there then is
          not listed.
        </p>
      )}
      {t.untracked.length > 0 && <p>Not tracked yet: {listing(t.untracked)}.</p>}
      {skipped.map((s) => (
        <p key={`${s.kind}-${s.reason}`} class="wokenotes__skip">
          Not checked in the last run: {WAKE_KIND_LABEL[s.kind]}. {s.reason}. Missing data is not the same as nothing new.
        </p>
      ))}
    </div>
  );
}

export default function Woke() {
  useTitle('Woke up');
  useKnobUrl();
  const level = useStore(knob);
  const loc = useLocation();
  const woke = useData(data.woke);
  const now = useNow(60_000);
  const kindParam = loc.search.get('kind');
  const kind: WakeKind | null = isWakeKind(kindParam) ? kindParam : null;
  const items = useMemo(() => (woke.status === 'ready' ? byKind(woke.data.items, kind) : []), [woke, kind]);
  const weeks = useMemo(() => byWeek(items), [items]);

  const [sel, setSel] = useState(-1);
  const selRef = useRef(-1);
  const focusNext = useRef(false);
  useEffect(() => {
    selRef.current = -1;
    setSel(-1);
  }, [kind]);
  useEffect(() => {
    const id = items[sel]?.id;
    if (!id || !focusNext.current) return;
    focusNext.current = false;
    requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-row-link="${id}"]`)?.focus());
  }, [sel]);
  const select = (i: number) => {
    selRef.current = i;
    setSel(i);
  };
  useListController({
    move: (d) => {
      if (items.length === 0) return;
      focusNext.current = true;
      select(Math.min(items.length - 1, Math.max(0, selRef.current + d)));
    },
    open: () => items[selRef.current] && navigate(cveHref(items[selRef.current].id)),
    watch: () => items[selRef.current] && watchVendorOf(items[selRef.current].row),
    copy: () => items[selRef.current] && void copyTicket(items[selRef.current].id),
  });

  const atom = new URL(`${FEEDS_BASE}woke.xml`, window.location.origin).href;
  const json = new URL(`${DATA_BASE}woke.json`, window.location.origin).href;
  const index = new Map(items.map((it, i) => [it.id, i]));

  return (
    <div class="page page--woke">
      <header class="page__head">
        <p class="eyebrow">Old CVEs, new evidence</p>
        <h1 class="page__title" tabIndex={-1}>
          Woke up
        </h1>
        <p class="page__lede">
          CVEs published more than 30 days ago that gained exploitation evidence in the last 30 days. The other views only show new CVEs, but attackers keep going after old ones.
        </p>
        <div class="page__actions">
          <a class="btn" href={atom}>
            <IconRss size={14} /> Atom feed
          </a>
          <button type="button" class="btn btn--ghost" onClick={() => void copyLink(atom, 'Feed URL')}>
            <IconCopy size={14} /> Copy feed URL
          </button>
          <a class="btn btn--ghost" href={json} target="_blank" rel="noopener noreferrer">
            <IconCode size={14} /> JSON
          </a>
        </div>
      </header>

      {woke.status === 'error' ? (
        woke.error instanceof DataError && woke.error.status === 404 ? (
          <EmptyState title="Not published yet">The first pipeline run with this feature has not finished. Check back after the next hourly run.</EmptyState>
        ) : (
          <ErrorState error={woke.error} onRetry={woke.retry} />
        )
      ) : woke.status !== 'ready' ? (
        <Loading label="Loading old CVEs that woke up" lines={6} height="72px" />
      ) : (
        <>
          <div class="wokefilter" role="group" aria-label="Kind of evidence">
            <div class="seg">
              <button type="button" class="seg__btn" aria-pressed={kind === null ? 'true' : 'false'} onClick={() => setQuery({ kind: null })}>
                All <span class="seg__count">{fmtInt(woke.data.items.length)}</span>
              </button>
              {WAKE_KINDS.map((k) => (
                <button key={k} type="button" class="seg__btn" aria-pressed={kind === k ? 'true' : 'false'} disabled={woke.data.counts[k] === 0 && kind !== k} onClick={() => setQuery({ kind: kind === k ? null : k })}>
                  {WAKE_KIND_LABEL[k]} <span class="seg__count">{fmtInt(woke.data.counts[k])}</span>
                </button>
              ))}
            </div>
          </div>
          <Notes woke={woke.data} />
          {items.length === 0 ? (
            <EmptyState title={kind ? `No ${WAKE_KIND_LABEL[kind]} signals in the last ${woke.data.days} days` : `Nothing woke up in the last ${woke.data.days} days`}>
              That can change any hour. Quiet is not the same as safe.
            </EmptyState>
          ) : (
            weeks.map(([week, group]) => (
              <section key={week} class="batchday" aria-labelledby={`wk-${week}`}>
                <header class="batchday__head">
                  <h2 class="batchday__date" id={`wk-${week}`}>
                    Week of {fmtDate(week)}
                  </h2>
                  <span class="batchday__sum">{plural(group.length, 'CVE')}</span>
                </header>
                <div class="rows">
                  {group.map((it) => {
                    const i = index.get(it.id) ?? -1;
                    return (
                      <CveRow
                        key={it.id}
                        row={it.row}
                        tier={tierAt(it.row, level)}
                        knob={level}
                        now={now}
                        selected={i === sel}
                        onSelect={() => i !== selRef.current && select(i)}
                        note={<WakeSignals signals={it.signals} />}
                      />
                    );
                  })}
                </div>
              </section>
            ))
          )}
          <p class="fineprint">
            A CVE counts when its first KEV listing, Exploit-DB entry, Metasploit module, Nuclei template or vetted PoC repo, or a threefold EPSS rise to 10% or more, came after it was already 30 days old.
            CVEs that were in KEV before the last {woke.data.days} days are left out: they never fell asleep. The row age is the time since publication.
          </p>
        </>
      )}
    </div>
  );
}
