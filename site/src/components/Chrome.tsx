/** Page chrome: header with navigation and data status, and the footer. */
import { Fragment } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import type { Meta } from '../../../shared/contract';
import { BRAND, REPO_URL } from '../../../shared/brand';
import { dataStatusTip, fmtAge, fmtDateTime } from '../format';
import { useData, useNow } from '../hooks';
import { data } from '../data';
import { href, type Route } from '../router';
import { overlay, theme, toggleTheme, useStore } from '../state';
import { Dialog } from './Dialog';
import { IconMoon, IconSearch, IconSource, IconSun, IconX, Mark } from './icons';

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
  /** One line under the label in the menu sheet. */
  hint: string;
}

/**
 * Every page, in three groups by what people come to do. Wide screens show all of them in one
 * row with a divider between groups; narrower ones get a menu button that opens the same groups
 * as a sheet, each page with one line on what it is. Ctrl K reaches every page either way.
 */
export const NAV_GROUPS: readonly { id: string; label: string; items: readonly NavLink[] }[] = [
  {
    id: 'act',
    label: 'Act on it',
    items: [
      { name: 'today', path: '', label: 'Today', hint: 'The few CVEs that matter now, and why' },
      { name: 'check', path: 'check', label: 'Check', hint: 'Am I affected? A repo, lockfile or SBOM' },
      { name: 'kev', path: 'kev', label: 'KEV Clock', hint: 'CISA due dates, counting down' },
      { name: 'woke', path: 'woke', label: 'Woke Up', hint: 'Old CVEs with new exploit evidence' },
    ],
  },
  {
    id: 'look',
    label: 'Look into it',
    items: [
      { name: 'surge', path: 'surge', label: 'Trends', hint: 'The surge in volume, and what it is not' },
      { name: 'explore', path: 'explore', label: 'Explore', hint: 'Every CVE of the window, by day' },
      { name: 'batches', path: 'batches', label: 'Patch days', hint: 'Batches and bulk releases' },
      { name: 'receipts', path: 'receipts', label: 'Receipts', hint: 'Every hit and miss, against CISA' },
    ],
  },
  {
    id: 'build',
    label: 'Build with it',
    items: [
      { name: 'mcp', path: 'mcp', label: 'MCP', hint: 'Verdicts for AI agents, one command' },
      { name: 'feeds', path: 'feeds', label: 'API', hint: 'Atom, iCalendar, JSON and llms.txt' },
      { name: 'method', path: 'method', label: 'Method', hint: 'The chips, their points, the blind spots' },
    ],
  },
];

/** The menu sheet for narrow screens: the same groups, each page with what it is for. */
function NavSheet({ open, onClose, route }: { open: boolean; onClose: () => void; route: Route }) {
  return (
    <Dialog open={open} onClose={onClose} label="Menu" class="dialog--sheet">
      <div class="sheet">
        <div class="sheet__top">
          <span class="brand">
            <Mark size={20} />
            <Wordmark class="brand__name" />
          </span>
          <button type="button" class="iconbtn" onClick={onClose} aria-label="Close the menu">
            <IconX />
          </button>
        </div>
        <button
          type="button"
          class="searchbtn sheet__search"
          onClick={() => {
            onClose();
            overlay.set('palette');
          }}
        >
          <IconSearch size={14} />
          <span>Search CVEs, vendors and pages</span>
        </button>
        <nav aria-label="All pages">
          {NAV_GROUPS.map((g, gi) => (
            <section key={g.id} class="sheet__group" style={{ '--g': gi }}>
              <h2 class="grouplabel__head sheet__glabel">
                <span class="grouplabel__n mono">{String(gi + 1).padStart(2, '0')}</span>
                <span class="grouplabel__name">{g.label}</span>
                <span class="grouplabel__rule" aria-hidden="true" />
              </h2>
              <ul class="sheet__list">
                {g.items.map((n, i) => (
                  <li key={n.name} style={{ '--i': gi * 4 + i }}>
                    <a class="sheet__item" href={href(n.path)} aria-current={route.name === n.name ? 'page' : undefined} onClick={onClose}>
                      <span class="sheet__name">{n.label}</span>
                      <span class="sheet__hint">{n.hint}</span>
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </nav>
      </div>
    </Dialog>
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
  const [sheet, setSheet] = useState(false);
  useEffect(() => setSheet(false), [route.name]);
  const el = useRef<HTMLElement>(null);
  const nav = useRef<HTMLElement>(null);
  // On narrow screens the nav is a scrolling row, so the current page can sit off-screen.
  // Bring its link into view (no smooth scroll) whenever the page changes.
  useEffect(() => {
    const row = nav.current;
    const link = row?.querySelector<HTMLElement>('.nav__link[aria-current="page"]');
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
          {NAV_GROUPS.map((g, gi) => (
            <Fragment key={g.id}>
              {gi > 0 && <span class="nav__sep" aria-hidden="true" />}
              {g.items.map((n) => (
                <a key={n.name} class="nav__link" href={href(n.path)} aria-current={route.name === n.name ? 'page' : undefined}>
                  {n.label}
                </a>
              ))}
            </Fragment>
          ))}
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
          <a class="iconbtn top__gh" href={REPO_URL} target="_blank" rel="noopener noreferrer nofollow" aria-label="Source code on GitHub (opens in a new tab)" data-tip="Source & data on GitHub">
            <IconSource />
          </a>
          <button type="button" class="iconbtn top__menu" onClick={() => setSheet(true)} aria-label="Menu: all pages" aria-haspopup="dialog" aria-expanded={sheet ? 'true' : 'false'}>
            <span class="burger" aria-hidden="true">
              <span />
              <span />
              <span />
            </span>
          </button>
        </div>
        <NavSheet open={sheet} onClose={() => setSheet(false)} route={route} />
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
          <a href={href('mcp')}>MCP Server</a>
          <a href={href('feeds')}>Feeds &amp; API</a>
          <a href={href('method')}>Method</a>
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
