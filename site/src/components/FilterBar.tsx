/** Filters for the Today feed: tiers, search, noise toggles, watchlist and the active chip. */
import { useEffect, useRef, useState } from 'preact/hooks';
import type { Tier } from '../../../shared/contract';
import { absoluteUrl, copyLink } from '../actions';
import type { FeedFilter, TierCounts } from '../filters';
import { fmtInt } from '../format';
import { useSearchTarget } from '../hooks';
import { href } from '../router';
import { toggleWatch, useStore, watchlist } from '../state';
import { chipDef, TIER_META } from '../tiers';
import { IconEye, IconLink, IconSearch, IconX } from './icons';
import { TierIcon } from './Tier';

const TOGGLABLE: readonly Tier[] = ['exploited', 'likely', 'watch'];

interface Props {
  filter: FeedFilter;
  onChange: (next: FeedFilter) => void;
  counts: TierCounts;
  shown: number;
}

export function FilterBar({ filter, onChange, counts, shown }: Props) {
  const searchRef = useSearchTarget();
  const set = (patch: Partial<FeedFilter>) => onChange({ ...filter, ...patch });
  const toggleTier = (t: Tier) => {
    const next = new Set(filter.tiers);
    if (next.has(t)) next.delete(t);
    else next.add(t);
    set({ tiers: next });
  };
  const chip = filter.chip ? chipDef(filter.chip) : undefined;
  return (
    <div class="filters" role="search" aria-label="Filter the signal">
      <div class="filters__row">
        <div class="seg seg--tiers" role="group" aria-label="Tiers">
          {TOGGLABLE.map((t) => (
            <button key={t} type="button" class={`seg__btn seg__btn--${t}`} aria-pressed={filter.tiers.has(t) ? 'true' : 'false'} onClick={() => toggleTier(t)}>
              <TierIcon tier={t} size={13} />
              {TIER_META[t].label}
              <span class="seg__count">{fmtInt(counts[t])}</span>
            </button>
          ))}
        </div>
        <label class="search">
          <IconSearch size={14} />
          <span class="sr-only">Search the signal</span>
          <input ref={searchRef} type="search" placeholder="Vendor, product, CVE ID…" value={filter.query} onInput={(e) => set({ query: e.currentTarget.value })} spellcheck={false} />
          {!filter.query && <kbd class="kbd">/</kbd>}
        </label>
      </div>
      <div class="filters__row filters__row--sub">
        <span class="filters__label" id="hide-label">
          Hide
        </span>
        <div class="toggles" role="group" aria-labelledby="hide-label">
          <Toggle on={filter.hideWordpress} onClick={() => set({ hideWordpress: !filter.hideWordpress })} label="WordPress" tip="Wordfence, WPScan and Patchstack records — about 15% of all volume" />
          <Toggle on={filter.hideKernel} onClick={() => set({ hideKernel: !filter.hideKernel })} label="Linux kernel" tip="Linux kernel CNA bug-fix CVEs" />
          <Toggle on={filter.hideAi} onClick={() => set({ hideAi: !filter.hideAi })} label="AI-credited" tip="CVEs whose credits name an AI system (information only)" />
        </div>
        <Watchlist watchOnly={filter.watchOnly} onWatchOnly={(v) => set({ watchOnly: v })} />
        {chip && (
          <button type="button" class="activechip" onClick={() => set({ chip: null })} aria-label={`Remove reason filter: ${chip.short}`}>
            Reason: <strong>{chip.short}</strong>
            <IconX size={12} />
          </button>
        )}
        <span class="filters__count" aria-live="polite">
          {fmtInt(shown)} shown
        </span>
      </div>
    </div>
  );
}

function Toggle({ on, onClick, label, tip }: { on: boolean; onClick: () => void; label: string; tip: string }) {
  return (
    <button type="button" class="toggle" aria-pressed={on ? 'true' : 'false'} onClick={onClick} data-tip={tip}>
      <span class="toggle__box" aria-hidden="true" />
      {label}
    </button>
  );
}

function Watchlist({ watchOnly, onWatchOnly }: { watchOnly: boolean; onWatchOnly: (v: boolean) => void }) {
  const list = useStore(watchlist);
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState('');
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('pointerdown', away);
    document.addEventListener('keydown', esc);
    return () => {
      document.removeEventListener('pointerdown', away);
      document.removeEventListener('keydown', esc);
    };
  }, [open]);
  const add = (e: Event) => {
    e.preventDefault();
    if (draft.trim() && !list.includes(draft.trim().toLowerCase())) toggleWatch(draft);
    setDraft('');
  };
  const share = `${absoluteUrl(href(''))}?watch=${encodeURIComponent(list.join(','))}`;
  return (
    <div class="watch" ref={root}>
      <button type="button" class={`watch__btn${list.length ? ' has-items' : ''}`} aria-expanded={open ? 'true' : 'false'} aria-controls="watch-panel" onClick={() => setOpen(!open)}>
        <IconEye size={14} />
        Watchlist
        <span class="seg__count">{list.length}</span>
      </button>
      {open && (
        <div class="watch__panel" id="watch-panel">
          <p class="watch__hint">Watched vendors and products bypass the knob. Stored only in this browser.</p>
          <form class="watch__add" onSubmit={add}>
            <input type="text" value={draft} onInput={(e) => setDraft(e.currentTarget.value)} placeholder="Add a vendor or product" aria-label="Vendor or product to watch" />
            <button type="submit" class="btn btn--sm">
              Add
            </button>
          </form>
          {list.length > 0 ? (
            <ul class="watch__list">
              {list.map((n) => (
                <li key={n}>
                  <span>{n}</span>
                  <button type="button" class="iconbtn iconbtn--sm" onClick={() => toggleWatch(n)} aria-label={`Stop watching ${n}`}>
                    <IconX size={12} />
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p class="watch__empty">Nothing yet. Press w on a selected row to watch its vendor.</p>
          )}
          <label class="watch__only">
            <input type="checkbox" checked={watchOnly} onChange={(e) => onWatchOnly(e.currentTarget.checked)} disabled={list.length === 0} />
            Only show my watchlist
          </label>
          {list.length > 0 && (
            <button type="button" class="btn btn--ghost btn--sm" onClick={() => void copyLink(share, 'Share link')}>
              <IconLink size={14} /> Copy share link
            </button>
          )}
        </div>
      )}
    </div>
  );
}
