/** Explore: every CVE in the window, searchable and filterable, URL-synced, virtualised. */
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { TIERS, type Row, type Tier } from '../../../shared/contract';
import { CHIPS } from '../../../shared/model';
import { copyTicket, watchVendorOf } from '../actions';
import { IconSearch, IconX } from '../components/icons';
import { CveRow } from '../components/Row';
import { EmptyState, ErrorState, Loading } from '../components/States';
import { TierIcon } from '../components/Tier';
import { revealRow, VirtualList } from '../components/VirtualList';
import { data } from '../data';
import { emptyCounts, matches, terms, tierAt } from '../filters';
import { cnaName, fmtInt } from '../format';
import { useData, useDebounced, useKnobUrl, useListController, useMediaQuery, useNow, useSearchTarget, useTitle } from '../hooks';
import { cveHref, navigate, setQuery, useLocation } from '../router';
import { isWatched, knob, useStore, watchlist } from '../state';
import { FAMILY_META, FAMILY_ORDER, TIER_META } from '../tiers';

type Sort = 'date' | 'score';

interface Params {
  q: string;
  tiers: ReadonlySet<Tier>;
  cna: string;
  vendor: string;
  chip: string;
  sort: Sort;
}

function readParams(search: URLSearchParams): Params {
  const tiers = new Set((search.get('tier') ?? '').split(',').filter((t): t is Tier => (TIERS as readonly string[]).includes(t)));
  return {
    q: search.get('q') ?? '',
    tiers,
    cna: search.get('cna') ?? '',
    vendor: search.get('vendor') ?? '',
    chip: search.get('chip') ?? '',
    sort: search.get('sort') === 'score' ? 'score' : 'date',
  };
}

export default function Explore() {
  useTitle('Explore');
  useKnobUrl();
  const loc = useLocation();
  const p = readParams(loc.search);
  const level = useStore(knob);
  const watch = useStore(watchlist);
  const index = useData(data.index);
  const meta = useData(data.meta);
  const now = useNow(60_000);
  const narrow = useMediaQuery('(max-width: 720px)');
  const rowHeight = narrow ? 118 : 92;
  const listRef = useRef<HTMLDivElement>(null);
  const searchRef = useSearchTarget();
  const [q, setQ] = useState(p.q);
  const debounced = useDebounced(q, 180);
  const [sel, setSel] = useState(-1);
  const focusNext = useRef(false);
  const selected = useRef<string | null>(null);

  useEffect(() => setQuery({ q: debounced.trim() || null }), [debounced]);
  useEffect(() => {
    if (p.q !== debounced) setQ(p.q);
    // Only follow external URL changes (back/forward, palette links).
  }, [p.q]);

  const rows: readonly Row[] = index.status === 'ready' ? index.data : [];
  const base = useMemo(() => {
    const ts = terms(p.q);
    const vendor = p.vendor.toLowerCase();
    return rows.filter((r) => (!p.cna || r.cna === p.cna) && (!vendor || r.v.toLowerCase() === vendor || r.p.toLowerCase() === vendor) && (!p.chip || r.c.includes(p.chip)) && matches(r, ts));
  }, [rows, p.q, p.cna, p.vendor, p.chip]);
  const tierCounts = useMemo(() => {
    const c = emptyCounts();
    for (const r of base) c[tierAt(r, level)]++;
    return c;
  }, [base, level]);
  const results = useMemo(() => {
    const out = p.tiers.size ? base.filter((r) => p.tiers.has(tierAt(r, level))) : [...base];
    if (p.sort === 'score') out.sort((a, b) => b.s - a.s || b.pub.localeCompare(a.pub));
    return out;
  }, [base, p.tiers, p.sort, level]);
  const cnaOptions = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of rows) m.set(r.cna, (m.get(r.cna) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [rows]);
  const vendorOptions = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of rows) if (r.v) m.set(r.v, (m.get(r.v) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 300);
  }, [rows]);

  const signature = `${p.q}|${[...p.tiers].join()}|${p.cna}|${p.vendor}|${p.chip}|${p.sort}|${level}`;
  useEffect(() => setSel(-1), [signature]);
  useEffect(() => {
    if (sel < 0) return;
    revealRow(listRef.current, sel, rowHeight);
    selected.current = results[sel]?.id ?? null;
    // The row mounts once the list re-renders at the new scroll position; quick presses can land
    // before that frame, so focus whatever is selected by then.
    requestAnimationFrame(() => {
      if (!focusNext.current || !selected.current) return;
      focusNext.current = false;
      document.querySelector<HTMLElement>(`[data-row-link="${selected.current}"]`)?.focus({ preventScroll: true });
    });
  }, [sel]);

  useListController({
    move: (d) => {
      if (!results.length) return;
      focusNext.current = true;
      setSel((s) => Math.min(results.length - 1, Math.max(0, s + d)));
    },
    open: () => results[sel] && navigate(cveHref(results[sel].id)),
    watch: () => results[sel] && watchVendorOf(results[sel]),
    copy: () => results[sel] && void copyTicket(results[sel].id),
  });

  const toggleTier = (t: Tier) => {
    const n = new Set(p.tiers);
    if (n.has(t)) n.delete(t);
    else n.add(t);
    setQuery({ tier: [...n].join(',') || null });
  };
  const anyFilter = p.q || p.tiers.size || p.cna || p.vendor || p.chip;
  const total = meta.status === 'ready' ? meta.data.counts.window_published : rows.length;

  return (
    <div class="page page--explore">
      <header class="page__head">
        <p class="eyebrow">The whole window</p>
        <h1 class="page__title" tabIndex={-1}>
          Explore
        </h1>
        <p class="page__lede">
          All {fmtInt(total)} CVEs published in the last 30 days — the noise included, so you can check what the knob leaves out.
        </p>
      </header>

      <div class="explore__controls" role="search" aria-label="Filter CVEs">
        <div class="filters__row">
          <label class="search search--lg">
            <IconSearch size={16} />
            <span class="sr-only">Search CVE ID, vendor, product or title</span>
            <input ref={searchRef} type="search" value={q} onInput={(e) => setQ(e.currentTarget.value)} placeholder="Search ID, vendor, product, title…" spellcheck={false} />
            {!q && <kbd class="kbd">/</kbd>}
          </label>
          <div class="seg" role="group" aria-label="Sort">
            {(['date', 'score'] as const).map((s) => (
              <button key={s} type="button" class="seg__btn" aria-pressed={p.sort === s ? 'true' : 'false'} onClick={() => setQuery({ sort: s === 'date' ? null : s })}>
                {s === 'date' ? 'Newest' : 'Score'}
              </button>
            ))}
          </div>
        </div>
        <div class="filters__row filters__row--sub">
          <div class="seg seg--tiers" role="group" aria-label="Tiers">
            {TIERS.map((t) => (
              <button key={t} type="button" class={`seg__btn seg__btn--${t}`} aria-pressed={p.tiers.has(t) ? 'true' : 'false'} onClick={() => toggleTier(t)}>
                <TierIcon tier={t} size={13} />
                {TIER_META[t].label}
                <span class="seg__count">{fmtInt(tierCounts[t])}</span>
              </button>
            ))}
          </div>
          <label class="select">
            <span>CNA</span>
            <select value={p.cna} onChange={(e) => setQuery({ cna: e.currentTarget.value || null })}>
              <option value="">All</option>
              {cnaOptions.map(([c, n]) => (
                <option key={c} value={c}>
                  {cnaName(c)} ({fmtInt(n)})
                </option>
              ))}
            </select>
          </label>
          <label class="select">
            <span>Vendor</span>
            <input list="vendor-options" value={p.vendor} onChange={(e) => setQuery({ vendor: e.currentTarget.value.trim() || null })} placeholder="Any" />
            <datalist id="vendor-options">
              {vendorOptions.map(([v]) => (
                <option key={v} value={v} />
              ))}
            </datalist>
          </label>
          <label class="select">
            <span>Reason</span>
            <select value={p.chip} onChange={(e) => setQuery({ chip: e.currentTarget.value || null })}>
              <option value="">Any</option>
              {FAMILY_ORDER.map((f) => (
                <optgroup key={f} label={FAMILY_META[f].label}>
                  {CHIPS.filter((c) => c.family === f && c.polarity !== 'unknown').map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.short}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </label>
          {anyFilter && (
            <button
              type="button"
              class="btn btn--ghost btn--sm"
              onClick={() => {
                setQ('');
                setQuery({ q: null, tier: null, cna: null, vendor: null, chip: null });
              }}
            >
              <IconX size={12} /> Reset
            </button>
          )}
          <span class="filters__count" aria-live="polite">
            {index.status === 'ready' ? `${fmtInt(results.length)} of ${fmtInt(rows.length)}` : ''}
          </span>
        </div>
      </div>

      {index.status === 'error' ? (
        <ErrorState error={index.error} onRetry={index.retry} />
      ) : index.status !== 'ready' ? (
        <Loading label={`Loading ${fmtInt(total)} CVEs`} lines={8} height="64px" />
      ) : results.length === 0 ? (
        <EmptyState title="No CVEs match">Try fewer filters — or a CVE ID from outside the window opens its own page.</EmptyState>
      ) : (
        <VirtualList
          key={signature}
          listRef={listRef}
          items={results}
          rowHeight={rowHeight}
          label="CVEs"
          render={(r, i) => (
            <CveRow
              row={r}
              tier={tierAt(r, level)}
              knob={level}
              now={now}
              watched={isWatched(watch, r)}
              selected={i === sel}
              activeChip={p.chip || null}
              onChip={(id) => setQuery({ chip: p.chip === id ? null : id })}
              onSelect={() => i !== sel && setSel(i)}
            />
          )}
        />
      )}
    </div>
  );
}
