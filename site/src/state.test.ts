import { describe, expect, it } from 'vitest';
import { KNOB_DEFAULT, KNOB_MAX, KNOB_MIN } from '../../shared/contract';
import { createStorage, createStore, isWatched, normalizeName, parseKnob, parseWatch } from './state';

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
