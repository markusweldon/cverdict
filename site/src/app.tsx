/** App shell: routes (Today eager, the rest lazy), global keyboard, focus and scroll management. */
import type { ComponentType } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { Footer, Header } from './components/Chrome';
import { IconRefresh } from './components/icons';
import { Palette } from './components/Palette';
import { ShortcutsHelp } from './components/Shortcuts';
import { ErrorState, Loading } from './components/States';
import { Toasts } from './components/Toasts';
import { TooltipLayer } from './components/Tooltip';
import { data, reloadFresh } from './data';
import { fmtDateTime } from './format';
import { useData } from './hooks';
import Today from './pages/Today';
import { href, navigate, onNavigate, savedScroll, scrollToHash, startRouter, useRoute, type Route } from './router';
import { clampSiteKnob, keyTargets, knob, overlay } from './state';

interface Lazy<P> {
  (props: P): preact.JSX.Element;
  preload(): Promise<void>;
}

/** Code-split page: renders a skeleton until its chunk arrives; preload() warms it up. */
function lazyPage<P extends object>(load: () => Promise<{ default: ComponentType<P> }>): Lazy<P> {
  let Page: ComponentType<P> | null = null;
  let pending: Promise<void> | null = null;
  const preload = () =>
    (pending ??= load().then(
      (m) => {
        Page = m.default;
      },
      (e: unknown) => {
        pending = null;
        throw e;
      },
    ));
  const Component = (props: P) => {
    const [, rerender] = useState(0);
    const [error, setError] = useState<Error | null>(null);
    useEffect(() => {
      if (!Page) preload().then(() => rerender((n) => n + 1), (e: unknown) => setError(e instanceof Error ? e : new Error(String(e))));
    }, []);
    if (error) return <ErrorState title="This page failed to load" error={new Error('A newer version of the site may have been deployed')} onRetry={() => window.location.reload()} />;
    if (!Page) return <Loading label="Loading page" lines={5} height="40px" class="page-skel" />;
    const Loaded = Page;
    return <Loaded {...props} />;
  };
  return Object.assign(Component, { preload });
}

const Cve = lazyPage(() => import('./pages/Cve'));
const Kev = lazyPage(() => import('./pages/Kev'));
const Woke = lazyPage(() => import('./pages/Woke'));
const Receipts = lazyPage(() => import('./pages/Receipts'));
const Batches = lazyPage(() => import('./pages/Batches'));
const Explore = lazyPage(() => import('./pages/Explore'));
const Check = lazyPage(() => import('./pages/Check'));
const Surge = lazyPage(() => import('./pages/Surge'));
const Method = lazyPage(() => import('./pages/Method'));
const Feeds = lazyPage(() => import('./pages/Feeds'));
const Mcp = lazyPage(() => import('./pages/Mcp'));
const NotFound = lazyPage(() => import('./pages/NotFound'));
// Check is not warmed: its chunk (parsers and version orderings) would add a request to every
// visit, and only people who open the page need it.
const LAZY = [Cve, Kev, Woke, Receipts, Batches, Explore, Surge, Method, Feeds, Mcp, NotFound];

function RouteView({ route }: { route: Route }) {
  switch (route.name) {
    case 'today':
      return <Today />;
    case 'cve':
      return <Cve key={route.id} id={route.id} />;
    case 'kev':
      return <Kev />;
    case 'woke':
      return <Woke />;
    case 'receipts':
      return <Receipts />;
    case 'batches':
      return <Batches />;
    case 'explore':
      return <Explore />;
    case 'check':
      return <Check />;
    case 'surge':
      return <Surge />;
    case 'method':
      return <Method />;
    case 'feeds':
      return <Feeds />;
    case 'mcp':
      return <Mcp />;
    default:
      return <NotFound path={route.path} />;
  }
}

const GO: Readonly<Record<string, string>> = { t: '', k: 'kev', w: 'woke', r: 'receipts', b: 'batches', e: 'explore', c: 'check', s: 'surge', m: 'method', f: 'feeds', a: 'mcp' };
const snap = (v: number, d: number) => clampSiteKnob(Math.round((v + d) / 5) * 5);

function useGlobalKeys(): void {
  useEffect(() => {
    let gAt = 0;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        overlay.set(overlay.get() === 'palette' ? null : 'palette');
        return;
      }
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || overlay.get()) return;
      const target = e.target instanceof Element ? e.target : document.body;
      const field = target.closest('input, textarea, select, [contenteditable=""], [contenteditable="true"]');
      if (field) {
        if (e.key === 'Escape') (field as HTMLElement).blur();
        return;
      }
      if (gAt && Date.now() - gAt < 1200) {
        gAt = 0;
        if (e.key in GO) {
          e.preventDefault();
          navigate(href(GO[e.key]));
        }
        return;
      }
      const list = keyTargets.list;
      switch (e.key) {
        case 'g':
          gAt = Date.now();
          return;
        case 'j':
          list?.move(1);
          break;
        case 'k':
          list?.move(-1);
          break;
        case 'o':
          list?.open();
          break;
        case 'Enter':
          if (target.closest('a, button, summary, [role="slider"], canvas, svg[tabindex]')) return;
          list?.open();
          break;
        case 'w':
          list?.watch();
          break;
        case 'c':
          if (keyTargets.copy) keyTargets.copy();
          else list?.copy();
          break;
        case '/':
          if (keyTargets.search?.isConnected) {
            keyTargets.search.focus();
            keyTargets.search.select();
          } else overlay.set('palette');
          break;
        case '?':
          overlay.set('help');
          break;
        case '[':
          knob.set((v) => snap(v, -5));
          break;
        case ']':
          knob.set((v) => snap(v, 5));
          break;
        default:
          return;
      }
      e.preventDefault();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);
}

/** Notices a newer hourly run while the tab stays open and offers a reload. */
function UpdateBanner() {
  const meta = useData(data.meta);
  const [newer, setNewer] = useState<string | null>(null);
  const loaded = meta.status === 'ready' ? meta.data.generated_at : null;
  useEffect(() => {
    if (!loaded) return;
    const check = () => {
      if (document.visibilityState !== 'visible') return;
      void data.latestGeneratedAt().then((at) => at && Date.parse(at) > Date.parse(loaded) && setNewer(at));
    };
    const id = window.setInterval(check, 10 * 60_000);
    document.addEventListener('visibilitychange', check);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', check);
    };
  }, [loaded]);
  if (!newer) return null;
  return (
    <div class="update" role="status">
      <span>Fresh data from the {fmtDateTime(newer)} run is available.</span>
      <button type="button" class="btn btn--sm btn--primary" onClick={reloadFresh}>
        <IconRefresh size={12} /> Reload
      </button>
    </div>
  );
}

/**
 * Move focus to the new page's h1 so screen readers announce it. Lazy pages and their data
 * arrive a little later, so wait a few frames for the heading before settling for <main>.
 * `outgoing` is the previous page's heading: it is skipped for one frame, which is enough for the
 * new route to replace it (a page that stays mounted, e.g. Explore with new filters, keeps it).
 */
function focusHeading(frames = 90, outgoing: Element | null = null): void {
  const h1 = document.querySelector<HTMLElement>('main h1[tabindex]');
  if (h1 && h1 !== outgoing && !document.querySelector('dialog[open]')) h1.focus({ preventScroll: true });
  else if (frames > 0) requestAnimationFrame(() => focusHeading(frames - 1, h1 === outgoing ? null : outgoing));
  else document.getElementById('main')?.focus({ preventScroll: true });
}

export function App() {
  const route = useRoute();
  useGlobalKeys();
  useEffect(() => {
    const stop = startRouter();
    if (window.location.hash) scrollToHash(window.location.hash);
    return stop;
  }, []);
  useEffect(() => {
    // Warm every page chunk once the first screen is idle.
    const warm = () => LAZY.forEach((p) => void p.preload().catch(() => undefined));
    const id = window.setTimeout(() => (typeof requestIdleCallback === 'function' ? requestIdleCallback(warm, { timeout: 4000 }) : warm()), 1500);
    return () => window.clearTimeout(id);
  }, []);
  useEffect(
    () =>
      onNavigate((l, kind) => {
        overlay.set(null);
        if (kind === 'replace') return;
        if (kind === 'push') {
          const outgoing = document.querySelector('main h1[tabindex]');
          requestAnimationFrame(() => focusHeading(90, outgoing));
        }
        requestAnimationFrame(() => {
          if (kind === 'pop') window.scrollTo(0, savedScroll());
          else if (l.hash) scrollToHash(l.hash);
          else window.scrollTo(0, 0);
        });
      }),
    [],
  );
  return (
    <>
      <Header route={route} />
      <UpdateBanner />
      <main id="main" class="main" tabIndex={-1}>
        <RouteView route={route} />
      </main>
      <Footer />
      <Palette />
      <ShortcutsHelp />
      <Toasts />
      <TooltipLayer />
    </>
  );
}
