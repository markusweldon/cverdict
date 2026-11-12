/** ⌘K command palette: jump to a CVE ID, a vendor, a page, or run an action. */
import type { ComponentChildren, VNode } from 'preact';
import { useMemo, useState } from 'preact/hooks';
import type { Row } from '../../../shared/contract';
import { KNOB_DEFAULT } from '../../../shared/contract';
import { data, normalizeCveId } from '../data';
import { matches, terms, tierAt } from '../filters';
import { fmtInt, vendorProduct } from '../format';
import { useData } from '../hooks';
import { cveHref, href, navigate } from '../router';
import { closeOverlay, knob, normalizeName, overlay, toast, toggleTheme, toggleWatch, useStore, watchlist } from '../state';
import { copyText } from '../ticket';
import { Dialog } from './Dialog';
import { IconArrowRight, IconEye, IconKeyboard, IconLayers, IconLink, IconMoon, IconRefresh, IconSearch } from './icons';
import { TierPill } from './Tier';

interface Item {
  id: string;
  group: 'CVE' | 'Vendor' | 'Page' | 'Action';
  label: string;
  hint?: string;
  row?: Row;
  icon?: ComponentChildren;
  run: () => void;
}

const PAGES: readonly [string, string, string][] = [
  ['Today', '', 'Signal, evidence bar, waterfall'],
  ['The Surge', 'surge', 'Volume since 1999'],
  ['KEV Clock', 'kev', 'CISA KEV due dates'],
  ['Woke Up', 'woke', 'Old CVEs with new exploit evidence'],
  ['Check Deps', 'check', 'Your dependencies, from an SBOM or lockfile'],
  ['Explore', 'explore', 'Every CVE in the window'],
  ['Batches', 'batches', 'Patch-day cohorts'],
  ['Receipts', 'receipts', 'Did we flag it before CISA did?'],
  ['Method', 'method', 'Formula, chips, sources'],
  ['MCP Server', 'mcp', 'AI agents: install, tools, limits'],
  ['Feeds & API', 'feeds', 'JSON, Atom, iCalendar'],
];

function buildItems(q: string, rows: readonly Row[]): Item[] {
  const go = (path: string) => () => navigate(href(path));
  const ts = terms(q);
  const out: Item[] = [];
  const id = normalizeCveId(q);
  if (id) out.push({ id: `open-${id}`, group: 'CVE', label: `Open ${id}`, hint: 'Go to the record', icon: <IconArrowRight size={14} />, run: () => navigate(cveHref(id)) });

  const cves = (q.trim() ? rows.filter((r) => r.id !== id && matches(r, ts)) : rows.filter((r) => r.x))
    .sort((a, b) => b.s - a.s || b.pub.localeCompare(a.pub))
    .slice(0, q.trim() ? 6 : 4);
  for (const r of cves) out.push({ id: r.id, group: 'CVE', label: r.id, hint: vendorProduct(r.v, r.p) || r.t, row: r, run: () => navigate(cveHref(r.id)) });

  if (q.trim() && !id) {
    const counts = new Map<string, { name: string; n: number }>();
    const needle = normalizeName(q);
    for (const r of rows) {
      for (const name of [r.v, r.p]) {
        if (!name || !normalizeName(name).includes(needle)) continue;
        const key = normalizeName(name);
        const e = counts.get(key) ?? { name, n: 0 };
        e.n++;
        counts.set(key, e);
      }
    }
    for (const v of [...counts.values()].sort((a, b) => b.n - a.n).slice(0, 4)) {
      out.push({ id: `vendor-${v.name}`, group: 'Vendor', label: v.name, hint: `${fmtInt(v.n)} in the signal · explore`, icon: <IconLayers size={14} />, run: () => navigate(`${href('explore')}?vendor=${encodeURIComponent(v.name)}`) });
    }
    const watched = watchlist.get().includes(needle);
    out.push({
      id: `watch-${needle}`,
      group: 'Action',
      label: `${watched ? 'Stop watching' : 'Watch'} “${q.trim()}”`,
      hint: 'Watched vendors and products always show, whatever the evidence bar',
      icon: <IconEye size={14} />,
      run: () => toast(toggleWatch(q) ? `Watching ${q.trim()}` : `Stopped watching ${q.trim()}`, 'info'),
    });
  }

  for (const [label, path, hint] of PAGES) {
    if (!ts.length || ts.every((t) => `${label} ${hint}`.toLowerCase().includes(t))) out.push({ id: `page-${path}`, group: 'Page', label, hint, icon: <IconArrowRight size={14} />, run: go(path) });
  }
  const actions: Item[] = [
    { id: 'theme', group: 'Action', label: 'Toggle light / dark theme', icon: <IconMoon size={14} />, run: toggleTheme },
    { id: 'help', group: 'Action', label: 'Keyboard shortcuts', hint: '?', icon: <IconKeyboard size={14} />, run: () => overlay.set('help') },
    { id: 'copy', group: 'Action', label: 'Copy link to this page', icon: <IconLink size={14} />, run: () => void copyText(window.location.href).then((ok) => toast(ok ? 'Link copied' : 'Could not copy', ok ? 'ok' : 'error')) },
    { id: 'knob', group: 'Action', label: `Reset the evidence bar to ${KNOB_DEFAULT}`, icon: <IconRefresh size={14} />, run: () => knob.set(KNOB_DEFAULT) },
  ];
  for (const a of actions) if (!ts.length || ts.every((t) => a.label.toLowerCase().includes(t))) out.push(a);
  return out;
}

export function Palette() {
  const open = useStore(overlay) === 'palette';
  const close = () => closeOverlay('palette');
  return (
    <Dialog open={open} onClose={close} label="Command palette" class="dialog--palette">
      <PaletteBody close={close} />
    </Dialog>
  );
}

function PaletteBody({ close }: { close: () => void }) {
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const signal = useData(data.signal);
  const index = data.index.peek();
  const rows = index ?? (signal.status === 'ready' ? signal.data : []);
  const items = useMemo(() => buildItems(q, rows), [q, rows]);
  const sel = Math.min(active, Math.max(0, items.length - 1));
  const run = (item: Item | undefined) => {
    if (!item) return;
    close();
    item.run();
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const d = e.key === 'ArrowDown' ? 1 : -1;
      setActive((sel + d + items.length) % Math.max(1, items.length));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      run(items[sel]);
    }
  };
  const level = useStore(knob);
  const list: VNode[] = [];
  items.forEach((item, i) => {
    if (item.group !== items[i - 1]?.group) {
      list.push(
        <li class="palette__group" role="presentation" key={`g-${item.group}-${i}`}>
          {item.group}
        </li>,
      );
    }
    list.push(
      <li
        key={item.id}
        id={`pal-${i}`}
        role="option"
        aria-selected={i === sel ? 'true' : 'false'}
        class={`palette__item${i === sel ? ' is-active' : ''}`}
        onPointerMove={() => i !== sel && setActive(i)}
        onClick={() => run(item)}
      >
        <span class="palette__icon">{item.row ? <TierPill tier={tierAt(item.row, level)} size="sm" /> : item.icon}</span>
        <span class={`palette__label${item.row ? ' mono' : ''}`}>{item.label}</span>
        {item.hint && <span class="palette__hint">{item.hint}</span>}
      </li>,
    );
  });
  return (
    <div class="palette">
      <div class="palette__search">
        <IconSearch size={16} />
        <input
          class="palette__input"
          autoFocus
          type="text"
          value={q}
          placeholder="CVE ID, vendor, product, page…"
          aria-label="Search"
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          aria-activedescendant={items[sel] ? `pal-${sel}` : undefined}
          aria-autocomplete="list"
          spellcheck={false}
          onInput={(e) => {
            setQ(e.currentTarget.value);
            setActive(0);
          }}
          onKeyDown={onKey}
        />
        <kbd class="kbd">esc</kbd>
      </div>
      <ul class="palette__list" id="palette-list" role="listbox" aria-label="Results">
        {items.length === 0 && <li class="palette__empty">No matches. Try a CVE ID like CVE-2026-12345.</li>}
        {list}
      </ul>
      <div class="palette__foot">
        <span>
          <kbd class="kbd">↑</kbd>
          <kbd class="kbd">↓</kbd> move
        </span>
        <span>
          <kbd class="kbd">↵</kbd> open
        </span>
        <span>{signal.status === 'loading' ? 'Loading the signal…' : index ? `${fmtInt(rows.length)} CVEs searchable` : `${fmtInt(rows.length)} signal CVEs searchable`}</span>
      </div>
    </div>
  );
}
