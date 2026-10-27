import type { RefObject } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { BRAND } from '../../shared/brand';
import { KNOB_DEFAULT } from '../../shared/contract';
import type { Loader } from './data';
import { setQuery } from './router';
import { keyTargets, knob, type ListController } from './state';

export type Resource<T> =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ready'; data: T }
  | { status: 'error'; error: Error };

/** Subscribe a component to a cached loader. `null` keeps it idle (lazy loading). */
export function useData<T>(loader: Loader<T> | null): Resource<T> & { retry(): void } {
  const initial = (): Resource<T> => {
    if (!loader) return { status: 'idle' };
    const v = loader.peek();
    return v === undefined ? { status: 'loading' } : { status: 'ready', data: v };
  };
  const [state, setState] = useState<Resource<T>>(initial);
  const [attempt, setAttempt] = useState(0);
  const key = loader?.key ?? null;
  useEffect(() => {
    if (!loader) {
      setState({ status: 'idle' });
      return;
    }
    const cached = loader.peek();
    if (cached !== undefined) {
      setState({ status: 'ready', data: cached });
      return;
    }
    let alive = true;
    setState({ status: 'loading' });
    loader.load().then(
      (data) => alive && setState({ status: 'ready', data }),
      (error: unknown) => alive && setState({ status: 'error', error: error instanceof Error ? error : new Error(String(error)) }),
    );
    return () => {
      alive = false;
    };
    // The loader object may be recreated every render; its key identifies the resource.
  }, [key, attempt]);
  return { ...state, retry: () => setAttempt((n) => n + 1) };
}

// One shared timer per interval keeps dozens of live countdowns cheap.
const clocks = new Map<number, { subs: Set<(now: number) => void>; id: number }>();
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    let clock = clocks.get(intervalMs);
    if (!clock) {
      const subs = new Set<(now: number) => void>();
      clock = { subs, id: window.setInterval(() => subs.forEach((fn) => fn(Date.now())), intervalMs) };
      clocks.set(intervalMs, clock);
    }
    clock.subs.add(setNow);
    setNow(Date.now());
    return () => {
      clock.subs.delete(setNow);
      if (clock.subs.size === 0) {
        window.clearInterval(clock.id);
        clocks.delete(intervalMs);
      }
    };
  }, [intervalMs]);
  return now;
}

export function useMediaQuery(query: string): boolean {
  const [match, setMatch] = useState(() => typeof window !== 'undefined' && window.matchMedia(query).matches);
  useEffect(() => {
    const mql = window.matchMedia(query);
    const on = () => setMatch(mql.matches);
    on();
    mql.addEventListener('change', on);
    return () => mql.removeEventListener('change', on);
  }, [query]);
  return match;
}

export const prefersReducedMotion = (): boolean => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/** Animate a number from its previous value (0 on mount) to `target` with an ease-out curve. */
export function useCountUp(target: number, durationMs = 600): number {
  const [value, setValue] = useState(() => (prefersReducedMotion() ? target : 0));
  const from = useRef(value);
  useEffect(() => {
    if (prefersReducedMotion()) {
      from.current = target;
      setValue(target);
      return;
    }
    const start = performance.now();
    const origin = from.current;
    let raf = 0;
    const tick = (t: number) => {
      const k = Math.min(1, (t - start) / durationMs);
      const eased = 1 - Math.pow(1 - k, 3);
      const v = Math.round(origin + (target - origin) * eased);
      from.current = v;
      setValue(v);
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);
  return value;
}

export function useTitle(title: string | null): void {
  useEffect(() => {
    document.title = title ? `${title} · ${BRAND.name}` : `${BRAND.name} — ${BRAND.tagline}`;
  }, [title]);
}

/** Register the on-screen list with the global keyboard handler while mounted. */
export function useListController(controller: ListController): void {
  const ref = useRef(controller);
  ref.current = controller;
  useEffect(() => {
    const proxy: ListController = {
      move: (d) => ref.current.move(d),
      open: () => ref.current.open(),
      watch: () => ref.current.watch(),
      copy: () => ref.current.copy(),
    };
    keyTargets.list = proxy;
    return () => {
      if (keyTargets.list === proxy) keyTargets.list = null;
    };
  }, []);
}

/** Register the page's search box as the `/` target while mounted. */
export function useSearchTarget(): (el: HTMLInputElement | null) => void {
  const el = useRef<HTMLInputElement | null>(null);
  useEffect(
    () => () => {
      if (keyTargets.search === el.current) keyTargets.search = null;
    },
    [],
  );
  return (node) => {
    el.current = node;
    if (node) keyTargets.search = node;
  };
}

export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}

/** Keep `?knob=` in the URL in step with the knob while a knob-driven page is mounted. */
export function useKnobUrl(): void {
  useEffect(() => {
    const write = (v: number) => setQuery({ knob: v === KNOB_DEFAULT ? null : String(v) });
    write(knob.get());
    let timer = 0;
    const off = knob.subscribe((v) => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => write(v), 160);
    });
    return () => {
      window.clearTimeout(timer);
      off();
    };
  }, []);
}

/** Content-box width of an always-mounted element, tracked with ResizeObserver (for crisp SVG charts). */
export function useWidth<T extends HTMLElement>(): [RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}
