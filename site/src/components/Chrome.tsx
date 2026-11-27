/** Page chrome: header with navigation and data status, and the footer. */
import { useEffect, useRef, useState } from 'preact/hooks';
import type { Meta } from '../../../shared/contract';
import { BRAND, REPO_URL } from '../../../shared/brand';
import { dataStatusTip, fmtAge, fmtDateTime } from '../format';
import { useData, useNow } from '../hooks';
import { data } from '../data';
import { href, type Route } from '../router';
import { overlay, theme, toggleTheme, useStore } from '../state';
import { IconChevronDown, IconMoon, IconSearch, IconSource, IconSun, Mark } from './icons';

export const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

/** The name as a wordmark: "CVE" bold, "rdict" regular, so the pun reads (BRAND.wordmark). */
function Wordmark({ class: cls, tag = 'span' }: { class: string; tag?: 'span' | 'p' }) {
  const [strong, rest] = BRAND.wordmark;
  const Tag = tag;
  return (
    <Tag class={`wordmark ${cls}`}>
      <span class="wordmark__strong">{strong}</span>
      {rest}
    </Tag>
  );
}

interface NavLink {
  name: Route['name'];
  path: string;
  label: string;
  /** One line under the label in a menu. */
  hint?: string;
}
type NavItem = NavLink | { menu: string; label: string; items: readonly NavLink[] };

/**
 * By what people come to do: what matters now (Today, Check), what is due and what changed (KEV
 * Clock, Woke Up), then search and proof (Explore, Receipts, The Surge). How it works and the
 * integrations sit in Docs, at the end of the row. Ctrl K reaches every page either way.
 */
const NAV: readonly NavItem[] = [
  { name: 'today', path: '', label: 'Today' },
  { name: 'check', path: 'check', label: 'Check' },
  { name: 'kev', path: 'kev', label: 'KEV Clock' },
  { name: 'woke', path: 'woke', label: 'Woke Up' },
  {
    menu: 'explore',
    label: 'Explore',
    items: [
      { name: 'explore', path: 'explore', label: 'All CVEs', hint: 'Every CVE of the window, by day' },
      { name: 'batches', path: 'batches', label: 'Patch days', hint: 'Batches and bulk releases' },
    ],
  },
  { name: 'receipts', path: 'receipts', label: 'Receipts' },
  { name: 'surge', path: 'surge', label: 'The Surge' },
  {
    menu: 'docs',
    label: 'Docs',
    items: [
      { name: 'method', path: 'method', label: 'Method', hint: 'The chips, their points, blind spots' },
      { name: 'mcp', path: 'mcp', label: 'MCP server', hint: 'Verdicts for AI agents' },
      { name: 'feeds', path: 'feeds', label: 'Feeds & API', hint: 'Atom, iCalendar, JSON and llms.txt' },
    ],
  },
];

/** A nav entry that opens a short list of pages. A disclosure, not an ARIA menu: the list holds plain links. */
function NavMenu({ item, route, row }: { item: Extract<NavItem, { menu: string }>; route: Route; row: { current: HTMLElement | null } }) {
  const [at, setAt] = useState<{ top: number; left: number } | null>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const id = `navmenu-${item.menu}`;
  const current = item.items.some((i) => i.name === route.name);
  const close = (focus = false) => {
    setAt(null);
    if (focus) btn.current?.focus();
  };
  // Fixed, so the scrolling nav row on narrow screens cannot clip it.
  const open = () => {
    const r = btn.current?.getBoundingClientRect();
    if (!r) return;
    setAt({ top: Math.round(r.bottom + 6), left: Math.round(Math.max(8, Math.min(r.left - 6, window.innerWidth - 268))) });
  };
  useEffect(() => close(), [route.name]);
  useEffect(() => {
    if (!at) return;
    const away = (e: PointerEvent) => {
      const t = e.target as Node;
      if (!btn.current?.contains(t) && !panel.current?.contains(t)) close();
    };
    const key = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      close(true);
    };
    const gone = () => close();
    const nav = row.current;
    document.addEventListener('pointerdown', away);
    document.addEventListener('keydown', key, true);
    window.addEventListener('resize', gone);
    nav?.addEventListener('scroll', gone);
    return () => {
      document.removeEventListener('pointerdown', away);
      document.removeEventListener('keydown', key, true);
      window.removeEventListener('resize', gone);
      nav?.removeEventListener('scroll', gone);
    };
  }, [at]);
  return (
    <>
      <button
        ref={btn}
        type="button"
        class={`nav__link nav__menubtn${current ? ' is-current' : ''}`}
        aria-expanded={at ? 'true' : 'false'}
        aria-controls={id}
        onClick={() => (at ? close() : open())}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (!at) open();
            requestAnimationFrame(() => panel.current?.querySelector<HTMLElement>('a')?.focus());
          }
        }}
      >
        {item.label}
        <IconChevronDown size={12} class="nav__chev" />
      </button>
      <div ref={panel} id={id} class="navmenu" hidden={!at} style={at ? { top: `${at.top}px`, left: `${at.left}px` } : undefined}>
        <ul class="navmenu__list">
          {item.items.map((i) => (
            <li key={i.name}>
              <a class="navmenu__item" href={href(i.path)} aria-current={route.name === i.name ? 'page' : undefined} onClick={() => close()}>
                <span class="navmenu__label">{i.label}</span>
                {i.hint && <span class="navmenu__hint">{i.hint}</span>}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </>
  );
}

/** Freshness of the last pipeline run: fresh < 2h, late < 6h, stale beyond. */
export function freshness(meta: Meta, now: number): 'fresh' | 'late' | 'stale' {
  const age = now - Date.parse(meta.generated_at);
  return age < 2 * 3_600_000 ? 'fresh' : age < 6 * 3_600_000 ? 'late' : 'stale';
}

function DataStatus() {
  const meta = useData(data.meta);
  const now = useNow(30_000);
  if (meta.status !== 'ready') return null;
  const state = freshness(meta.data, now);
  return (
    <a class={`status status--${state}`} href={href('method#sources')} data-tip={dataStatusTip(meta.data)}>
      <span class="status__dot" aria-hidden="true" />
      <span class="status__text">
        <span class="sr-only">Data age: </span>
        {fmtAge(meta.data.generated_at, now)}
      </span>
    </a>
  );
}

export function Header({ route }: { route: Route }) {
  const mode = useStore(theme);
  const el = useRef<HTMLElement>(null);
  const nav = useRef<HTMLElement>(null);
  // On narrow screens the nav is a scrolling row, so the current page can sit off-screen.
  // Bring its link into view (no smooth scroll) whenever the page changes.
  useEffect(() => {
    const row = nav.current;
    const link = row?.querySelector<HTMLElement>('.nav__link[aria-current="page"], .nav__link.is-current');
    if (!row || !link || row.scrollWidth <= row.clientWidth) return;
    const left = link.getBoundingClientRect().left - row.getBoundingClientRect().left + row.scrollLeft;
    const right = left + link.offsetWidth;
    if (left < row.scrollLeft || right > row.scrollLeft + row.clientWidth) row.scrollLeft = Math.max(0, left - (row.clientWidth - link.offsetWidth) / 2);
  }, [route.name]);
  // Sticky bars sit right under the header whatever its real height (it wraps on phones).
  useEffect(() => {
    const top = el.current;
    if (!top) return;
    const root = document.documentElement;
    const set = () => root.style.setProperty('--top-h', `${top.offsetHeight - 1}px`);
    // Set it now too, so a hash jump on first load already sees it before the observer's first callback.
    set();
    const ro = new ResizeObserver(set);
    ro.observe(top);
    return () => {
      ro.disconnect();
      root.style.removeProperty('--top-h');
    };
  }, []);
  return (
    <header class="top" ref={el}>
      <a class="skip" href="#main">
        Skip to content
      </a>
      <div class="top__inner">
        <a class="brand" href={href('')} aria-label={`${BRAND.name}, Today`}>
          <Mark size={22} />
          <Wordmark class="brand__name" />
        </a>
        <DataStatus />
        <nav class="nav" aria-label="Primary" ref={nav}>
          {NAV.map((n) =>
            'menu' in n ? (
              <NavMenu key={n.menu} item={n} route={route} row={nav} />
            ) : (
              <a key={n.name} class="nav__link" href={href(n.path)} aria-current={route.name === n.name ? 'page' : undefined}>
                {n.label}
              </a>
            ),
          )}
        </nav>
        <div class="top__actions">
          <button type="button" class="searchbtn" onClick={() => overlay.set('palette')} aria-label="Search CVEs, vendors and pages" aria-keyshortcuts={isMac ? 'Meta+K' : 'Control+K'}>
            <IconSearch size={14} />
            <span class="searchbtn__text">Search</span>
            <kbd class="kbd">{isMac ? '⌘K' : 'Ctrl K'}</kbd>
          </button>
          <button type="button" class="iconbtn" onClick={toggleTheme} aria-label={mode === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} data-tip={mode === 'dark' ? 'Light theme' : 'Dark theme'}>
            {mode === 'dark' ? <IconSun /> : <IconMoon />}
          </button>
          <a class="iconbtn" href={REPO_URL} target="_blank" rel="noopener noreferrer nofollow" aria-label="Source code on GitHub (opens in a new tab)" data-tip="Source & data on GitHub">
            <IconSource />
          </a>
        </div>
      </div>
    </header>
  );
}

export function Footer() {
  const meta = useData(data.meta);
  return (
    <footer class="foot">
      <div class="foot__inner">
        <div class="foot__brand">
          <Mark size={18} />
          <div>
            <Wordmark class="foot__name" tag="p" />
            <p class="foot__tag">{BRAND.tagline}</p>
          </div>
        </div>
        <p class="foot__text">
          Built only from free public data: CVE List V5, CISA KEV and Vulnrichment, ENISA EU KEV, the CIRCL (CC0) and SiberKapan (CC-BY-4.0) catalogs, FIRST EPSS, Metasploit, Nuclei, Exploit-DB, PoC-in-GitHub and, for the <a href={href('check')}>Check</a> page, OSV.dev advisories. Quiet ≠ safe. Not in KEV ≠ not exploited. Not affiliated with
          CISA, ENISA, CIRCL, MITRE, FIRST or any vendor.
        </p>
        <nav class="foot__links" aria-label="Footer">
          <a href={href('method')}>Method</a>
          <a href={href('feeds')}>Feeds &amp; API</a>
          <a href={href('mcp')}>MCP Server</a>
          <a href={REPO_URL} target="_blank" rel="noopener noreferrer nofollow">
            Source
          </a>
          <a href={`${REPO_URL}/issues`} target="_blank" rel="noopener noreferrer nofollow">
            Report an issue
          </a>
          <a href={`${REPO_URL}/blob/main/LICENSE`} target="_blank" rel="noopener noreferrer nofollow">
            MIT license
          </a>
        </nav>
        {meta.status === 'ready' && (
          <p class="foot__meta mono">
            model {meta.data.score_model} · schema v{meta.data.schema_version} · run {fmtDateTime(meta.data.generated_at)}
          </p>
        )}
      </div>
    </footer>
  );
}
