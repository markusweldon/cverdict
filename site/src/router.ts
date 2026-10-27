/**
 * History API router. Base-path aware (Vite `BASE_URL`, e.g. "/" on Vercel, "/<repo>/" on GitHub
 * Pages); intercepts same-origin <a> clicks; restores scroll on back/forward.
 */
import { useEffect, useState } from 'preact/hooks';
import { normalizeCveId } from './data';

export const BASE: string = import.meta.env.BASE_URL;

export type Route =
  | { name: 'today' }
  | { name: 'cve'; id: string }
  | { name: 'kev' }
  | { name: 'batches' }
  | { name: 'explore' }
  | { name: 'surge' }
  | { name: 'method' }
  | { name: 'feeds' }
  | { name: 'notfound'; path: string };

const STATIC: Readonly<Record<string, Route['name']>> = {
  '': 'today',
  kev: 'kev',
  batches: 'batches',
  explore: 'explore',
  surge: 'surge',
  method: 'method',
  feeds: 'feeds',
};

/** Path inside the app, without the base and without leading/trailing slashes: "cve/CVE-2026-1". */
export function appPath(pathname: string, base: string = BASE): string | null {
  const root = base.endsWith('/') ? base : `${base}/`;
  if (pathname === root.slice(0, -1)) return '';
  if (!pathname.startsWith(root)) return null;
  return pathname.slice(root.length).replace(/\/+$/, '');
}

export function parsePath(pathname: string, base: string = BASE): Route {
  const path = appPath(pathname, base);
  if (path === null) return { name: 'notfound', path: pathname };
  const fixed = STATIC[path];
  if (fixed) return { name: fixed } as Route;
  const m = /^cve\/([^/]+)$/i.exec(path);
  if (m) {
    let raw: string;
    try {
      raw = decodeURIComponent(m[1]);
    } catch {
      raw = m[1];
    }
    return { name: 'cve', id: normalizeCveId(raw) ?? raw };
  }
  return { name: 'notfound', path: `/${path}` };
}

/** Build an in-app href: href('cve/CVE-2026-1') → "/<base>/cve/CVE-2026-1". */
export function href(path: string, base: string = BASE): string {
  return `${base}${path.replace(/^\/+/, '')}`;
}

export const cveHref = (id: string): string => href(`cve/${id}`);

/**
 * Whether a link should be handled by the router: same origin, inside the base path, and not a
 * static file (data/, feeds/, anything with an extension).
 */
export function isAppUrl(url: URL, origin: string, base: string = BASE): boolean {
  if (url.origin !== origin) return false;
  const path = appPath(url.pathname, base);
  if (path === null) return false;
  return !/^(data|feeds|assets)(\/|$)/.test(path) && !/\.[a-z0-9]+$/i.test(path);
}

// ── live location ──

export interface Location {
  path: string;
  search: URLSearchParams;
  hash: string;
  route: Route;
}

function snapshot(): Location {
  return {
    path: window.location.pathname,
    search: new URLSearchParams(window.location.search),
    hash: window.location.hash,
    route: parsePath(window.location.pathname),
  };
}

type Listener = (loc: Location, kind: 'push' | 'replace' | 'pop') => void;
const listeners = new Set<Listener>();
let current: Location | null = null;

function emit(kind: 'push' | 'replace' | 'pop'): void {
  current = snapshot();
  for (const fn of listeners) fn(current, kind);
}

export function currentLocation(): Location {
  return (current ??= snapshot());
}

export function onNavigate(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function useLocation(): Location {
  const [loc, setLoc] = useState(currentLocation);
  useEffect(() => onNavigate((l) => setLoc(l)), []);
  return loc;
}

/** Navigate inside the app. `to` is an absolute path (already including the base) or a full URL. */
export function navigate(to: string, opts: { replace?: boolean } = {}): void {
  const url = new URL(to, window.location.href);
  const next = url.pathname + url.search + url.hash;
  if (next === window.location.pathname + window.location.search + window.location.hash) return;
  if (opts.replace) {
    history.replaceState(history.state, '', next);
    emit('replace');
    return;
  }
  // Remember where we were so Back restores it.
  history.replaceState({ ...(history.state ?? {}), scrollY: window.scrollY }, '');
  history.pushState({ scrollY: 0 }, '', next);
  emit('push');
}

/** Merge query parameters into the current URL without adding a history entry. null deletes. */
export function setQuery(updates: Readonly<Record<string, string | null>>): void {
  const params = new URLSearchParams(window.location.search);
  for (const [k, v] of Object.entries(updates)) {
    if (v === null || v === '') params.delete(k);
    else params.set(k, v);
  }
  const qs = params.toString();
  const next = `${window.location.pathname}${qs ? `?${qs}` : ''}${window.location.hash}`;
  if (next !== window.location.pathname + window.location.search + window.location.hash) {
    history.replaceState(history.state, '', next);
    emit('replace');
  }
}

/** Install the click interceptor and popstate handler. Returns a cleanup function. */
export function startRouter(): () => void {
  history.scrollRestoration = 'manual';
  const onClick = (e: MouseEvent) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = (e.target as Element | null)?.closest?.('a');
    if (!a || !a.href || a.hasAttribute('download') || (a.target && a.target !== '_self')) return;
    const url = new URL(a.href);
    if (!isAppUrl(url, window.location.origin)) return;
    e.preventDefault();
    if (url.pathname === window.location.pathname && url.search === window.location.search && url.hash) {
      history.replaceState(history.state, '', url.hash);
      document.getElementById(decodeURIComponent(url.hash.slice(1)))?.scrollIntoView({ block: 'start' });
      emit('replace');
      return;
    }
    navigate(url.href);
  };
  const onPop = () => emit('pop');
  document.addEventListener('click', onClick);
  window.addEventListener('popstate', onPop);
  return () => {
    document.removeEventListener('click', onClick);
    window.removeEventListener('popstate', onPop);
  };
}

/** Scroll position saved for the current history entry (set on push, read on pop). */
export function savedScroll(): number {
  const y = (history.state as { scrollY?: unknown } | null)?.scrollY;
  return typeof y === 'number' ? y : 0;
}
