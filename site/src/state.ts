/**
 * App-wide state: tiny observable stores plus the per-viewer conveniences kept in localStorage
 * (watchlist, theme, last visit). Every storage access is guarded: private windows and blocked
 * storage must never break the page.
 */
import { useEffect, useState } from 'preact/hooks';
import { KNOB_DEFAULT, type Row } from '../../shared/contract';

export interface Store<T> {
  get(): T;
  set(next: T | ((prev: T) => T)): void;
  subscribe(fn: (value: T) => void): () => void;
}

export function createStore<T>(initial: T): Store<T> {
  let value = initial;
  const subs = new Set<(value: T) => void>();
  return {
    get: () => value,
    set(next) {
      const v = typeof next === 'function' ? (next as (prev: T) => T)(value) : next;
      if (Object.is(v, value)) return;
      value = v;
      for (const fn of subs) fn(v);
    },
    subscribe(fn) {
      subs.add(fn);
      return () => subs.delete(fn);
    },
  };
}

export function useStore<T>(store: Store<T>): T {
  const [value, setValue] = useState(store.get);
  useEffect(() => {
    setValue(store.get());
    return store.subscribe(setValue);
  }, [store]);
  return value;
}

const browser = typeof window !== 'undefined';

/** localStorage scoped to the deployment's base path (several forks can share one github.io origin). */
export function createStorage(get: () => Storage | undefined, prefix: string) {
  return {
    get(key: string): string | null {
      try {
        return get()?.getItem(prefix + key) ?? null;
      } catch {
        return null;
      }
    },
    set(key: string, value: string): void {
      try {
        get()?.setItem(prefix + key, value);
      } catch {
        // Storage full or blocked: the setting simply does not persist.
      }
    },
  };
}
export const storage = createStorage(() => (browser ? window.localStorage : undefined), import.meta.env.BASE_URL);

const initialParams = () => new URLSearchParams(browser ? window.location.search : '');

// ── knob (the evidence bar) ──

/**
 * The site's dial runs 35 to 65. The API, MCP and pipeline still accept KNOB_MIN..KNOB_MAX
 * (30 to 80); outside 35 to 65 the list barely changes or floods (docs/SCORING.md).
 */
export const SITE_KNOB_MIN = 35;
export const SITE_KNOB_MAX = 65;

/** Clamp any knob value to the site's range. */
export const clampSiteKnob = (n: number): number => Math.min(SITE_KNOB_MAX, Math.max(SITE_KNOB_MIN, n));

/** One step of the [ and ] keys: to the next multiple of 5 in that direction, so 47 goes to 45 or 50, never 40. */
export function stepKnob(v: number, dir: -1 | 1): number {
  return clampSiteKnob(dir < 0 ? Math.ceil(v / 5 - 1) * 5 : Math.floor(v / 5 + 1) * 5);
}

export function parseKnob(raw: string | null): number {
  if (raw === null || raw.trim() === '') return KNOB_DEFAULT;
  const n = Number(raw);
  if (!Number.isFinite(n)) return KNOB_DEFAULT;
  return clampSiteKnob(Math.round(n));
}

/** Low to high, the same way the dial turns. */
export const KNOB_PRESETS = [
  { label: 'More', value: 40 },
  { label: 'Default', value: KNOB_DEFAULT },
  { label: 'Fewer', value: 60 },
] as const;

export const knob = createStore(parseKnob(initialParams().get('knob')));

// ── watchlist (vendors and products) ──

export const normalizeName = (s: string): string => s.trim().toLowerCase().replace(/\s+/g, ' ');

export function parseWatch(raw: string | null): string[] {
  if (!raw) return [];
  const out: string[] = [];
  for (const part of raw.split(',')) {
    const n = normalizeName(part);
    if (n && n.length <= 80 && !out.includes(n)) out.push(n);
  }
  return out.slice(0, 50);
}

function readStoredWatch(): string[] {
  try {
    const v: unknown = JSON.parse(storage.get('watch') ?? '[]');
    return Array.isArray(v) ? parseWatch(v.filter((x): x is string => typeof x === 'string').join(',')) : [];
  } catch {
    return [];
  }
}

/** Saved watchlist merged with any shared `?watch=` list. */
export const watchlist = createStore<string[]>(parseWatch([...readStoredWatch(), ...parseWatch(initialParams().get('watch'))].join(',')));
watchlist.subscribe((list) => storage.set('watch', JSON.stringify(list)));
// Adopt a shared list once: save the merge and drop the parameter, or every reload would re-add
// whatever the viewer has removed since.
if (browser && initialParams().has('watch')) {
  storage.set('watch', JSON.stringify(watchlist.get()));
  const url = new URL(window.location.href);
  url.searchParams.delete('watch');
  history.replaceState(history.state, '', url.pathname + url.search + url.hash);
}

export function isWatched(list: readonly string[], row: Pick<Row, 'v' | 'p'>): boolean {
  if (list.length === 0) return false;
  return (row.v !== '' && list.includes(normalizeName(row.v))) || (row.p !== '' && list.includes(normalizeName(row.p)));
}

/** Toggle a vendor/product; returns whether it is now watched. */
export function toggleWatch(name: string): boolean {
  const n = normalizeName(name);
  if (!n) return false;
  const watched = !watchlist.get().includes(n);
  watchlist.set((list) => (watched ? [...list, n] : list.filter((x) => x !== n)));
  return watched;
}

// ── theme ──

export type Theme = 'dark' | 'light';

function initialTheme(): Theme {
  if (!browser) return 'dark';
  const attr = document.documentElement.dataset.theme;
  if (attr === 'dark' || attr === 'light') return attr;
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

const THEME_BG: Readonly<Record<Theme, string>> = { dark: '#0A0B0D', light: '#FAFAF9' };

export const theme = createStore<Theme>(initialTheme());
theme.subscribe((t) => {
  document.documentElement.dataset.theme = t;
  for (const m of document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]')) m.content = THEME_BG[t];
});

/** An explicit choice is remembered; until then the site follows the OS setting. */
export function toggleTheme(): void {
  const next: Theme = theme.get() === 'dark' ? 'light' : 'dark';
  storage.set('theme', next);
  theme.set(next);
}

// ── "since your last visit" ──

/** When this browser last opened the site (read once, before this visit is recorded). */
export const previousVisit: number | null = (() => {
  const raw = Number(storage.get('last-visit'));
  if (browser) storage.set('last-visit', String(Date.now()));
  return Number.isFinite(raw) && raw > 0 ? raw : null;
})();

// ── toasts ──

export interface Toast {
  id: number;
  text: string;
  tone: 'ok' | 'error' | 'info';
}
export const toasts = createStore<Toast[]>([]);
let toastId = 0;
export function toast(text: string, tone: Toast['tone'] = 'ok'): void {
  const id = ++toastId;
  toasts.set((list) => [...list.slice(-2), { id, text, tone }]);
  setTimeout(() => toasts.set((list) => list.filter((t) => t.id !== id)), 2600);
}

// ── overlays & keyboard targets ──

export type Overlay = 'palette' | 'help';
export const overlay = createStore<Overlay | null>(null);

/**
 * Close `which` if it is still the open overlay. A dialog's close event fires after the switch to
 * another overlay (palette → help), and must not close the new one.
 */
export const closeOverlay = (which: Overlay): void => overlay.set((v) => (v === which ? null : v));

/** Implemented by whichever list is on screen; the global key handler drives it. */
export interface ListController {
  move(delta: number): void;
  open(): void;
  watch(): void;
  copy(): void;
}

export const keyTargets: { list: ListController | null; search: HTMLInputElement | null; copy: (() => void) | null } = {
  list: null,
  search: null,
  copy: null,
};
