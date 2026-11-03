/** Page chrome: header with navigation and data status, and the footer. */
import { useEffect, useRef } from 'preact/hooks';
import type { Meta } from '../../../shared/contract';
import { BRAND, REPO_URL } from '../../../shared/brand';
import { dataStatusTip, fmtAge, fmtDateTime } from '../format';
import { useData, useNow } from '../hooks';
import { data } from '../data';
import { href, type Route } from '../router';
import { overlay, theme, toggleTheme, useStore } from '../state';
import { IconMoon, IconSearch, IconSource, IconSun, Mark } from './icons';

export const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

const NAV: readonly { name: Route['name']; path: string; label: string }[] = [
  { name: 'today', path: '', label: 'Today' },
  { name: 'kev', path: 'kev', label: 'KEV Clock' },
  { name: 'woke', path: 'woke', label: 'Woke Up' },
  { name: 'explore', path: 'explore', label: 'Explore' },
  { name: 'check', path: 'check', label: 'Check Deps' },
  { name: 'batches', path: 'batches', label: 'Batches' },
  { name: 'receipts', path: 'receipts', label: 'Receipts' },
  { name: 'method', path: 'method', label: 'Method' },
  { name: 'surge', path: 'surge', label: 'The Surge' },
  { name: 'feeds', path: 'feeds', label: 'Feeds & API' },
];

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
    const link = row?.querySelector<HTMLElement>('[aria-current="page"]');
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
          <span class="brand__name">{BRAND.name}</span>
        </a>
        <DataStatus />
        <nav class="nav" aria-label="Primary" ref={nav}>
          {NAV.map((n) => (
            <a key={n.name} class="nav__link" href={href(n.path)} aria-current={route.name === n.name ? 'page' : undefined}>
              {n.label}
            </a>
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
            <p class="foot__name">{BRAND.name}</p>
            <p class="foot__tag">{BRAND.tagline}</p>
          </div>
        </div>
        <p class="foot__text">
          Built only from free public data: CVE List V5, CISA KEV and Vulnrichment, FIRST EPSS, Metasploit, Nuclei, Exploit-DB, PoC-in-GitHub and, for the Check Deps page, OSV.dev advisories. Quiet ≠ safe. Not in KEV ≠ not exploited. Not affiliated with
          CISA, MITRE, FIRST or any vendor.
        </p>
        <nav class="foot__links" aria-label="Footer">
          <a href={href('method')}>Method</a>
          <a href={href('feeds')}>Feeds &amp; API</a>
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
