import { afterEach, describe, expect, it, vi } from 'vitest';
import { KNOB_DEFAULT, KNOB_MAX, KNOB_MIN } from '../../shared/contract';
import { closeOverlay, createStorage, createStore, isWatched, normalizeName, overlay, parseKnob, parseWatch } from './state';

describe('parseKnob', () => {
  it('clamps, rounds and falls back to the default', () => {
    expect(parseKnob(null)).toBe(KNOB_DEFAULT);
    expect(parseKnob('')).toBe(KNOB_DEFAULT);
    expect(parseKnob('abc')).toBe(KNOB_DEFAULT);
    expect(parseKnob('42.6')).toBe(43);
    expect(parseKnob('5')).toBe(KNOB_MIN);
    expect(parseKnob('1e9')).toBe(KNOB_MAX);
  });
});

describe('watchlist', () => {
  it('parses shared lists: trimmed, lower-cased, deduplicated, bounded', () => {
    expect(parseWatch(' Fortinet,ivanti ,, FORTINET,Connect  Secure')).toEqual(['fortinet', 'ivanti', 'connect secure']);
    expect(parseWatch(null)).toEqual([]);
    expect(parseWatch(Array.from({ length: 80 }, (_, i) => `v${i}`).join(','))).toHaveLength(50);
    expect(parseWatch('x'.repeat(81))).toEqual([]);
  });

  it('matches a row by vendor or product', () => {
    const row = { v: 'Fortinet', p: 'FortiOS' };
    expect(isWatched(['fortinet'], row)).toBe(true);
    expect(isWatched(['fortios'], row)).toBe(true);
    expect(isWatched(['ivanti'], row)).toBe(false);
    expect(isWatched([''], { v: '', p: '' })).toBe(false);
    expect(normalizeName('  Palo   Alto ')).toBe('palo alto');
  });
});

describe('createStore', () => {
  it('notifies subscribers on change only', () => {
    const s = createStore(1);
    const seen: number[] = [];
    const off = s.subscribe((v) => seen.push(v));
    s.set(2);
    s.set(2);
    s.set((v) => v + 1);
    off();
    s.set(9);
    expect(seen).toEqual([2, 3]);
    expect(s.get()).toBe(9);
  });
});

describe('createStorage', () => {
  it('prefixes keys and survives storage that throws', () => {
    const map = new Map<string, string>();
    const ok = createStorage(() => ({ getItem: (k: string) => map.get(k) ?? null, setItem: (k: string, v: string) => void map.set(k, v) }) as unknown as Storage, '/repo/');
    ok.set('theme', 'light');
    expect(map.get('/repo/theme')).toBe('light');
    expect(ok.get('theme')).toBe('light');

    const broken = createStorage(() => {
      throw new DOMException('denied', 'SecurityError');
    }, '/');
    expect(broken.get('theme')).toBeNull();
    expect(() => broken.set('theme', 'dark')).not.toThrow();
  });
});

describe('closeOverlay', () => {
  it('closes only the overlay it names, so a late close event cannot close its successor', () => {
    overlay.set('palette');
    overlay.set('help');
    closeOverlay('palette');
    expect(overlay.get()).toBe('help');
    closeOverlay('help');
    expect(overlay.get()).toBeNull();
  });
});

describe('a shared ?watch= list', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('is merged into the saved list once, then dropped from the URL', async () => {
    const saved = new Map([['/watch', '["fortinet"]']]);
    const urls: string[] = [];
    const href = 'https://site.example/?watch=ivanti,Fortinet&knob=40#feed';
    vi.stubGlobal('window', {
      location: { href, search: new URL(href).search },
      localStorage: { getItem: (k: string) => saved.get(k) ?? null, setItem: (k: string, v: string) => saved.set(k, v) },
      matchMedia: () => ({ matches: false }),
    });
    vi.stubGlobal('document', { documentElement: { dataset: {} }, querySelectorAll: () => [] });
    vi.stubGlobal('history', { state: { scrollY: 120 }, replaceState: (_state: unknown, _title: string, url: string) => urls.push(url) });
    vi.resetModules();
    const fresh = await import('./state');
    expect(fresh.watchlist.get()).toEqual(['fortinet', 'ivanti']);
    // Saved right away: removing an item later and reloading must not bring it back.
    expect(JSON.parse(saved.get('/watch')!)).toEqual(['fortinet', 'ivanti']);
    expect(urls).toEqual(['/?knob=40#feed']);
    expect(fresh.knob.get()).toBe(40);
  });
});
