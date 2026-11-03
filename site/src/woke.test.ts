import { describe, expect, it } from 'vitest';
import type { Row, WakeSignal, WokeItem } from '../../shared/contract';
import { byKind, byWeek, firstSeenTip, isWakeKind, listing, mostUrgent, trackingNote, wakeSentence, weekOf, wokeWithin } from './woke';

const row = (id: string, o: Partial<Row> = {}): Row => ({
  id, pub: '2021-03-01T00:00:00Z', cna: 'acme', v: 'Acme', p: 'Widget', t: 't', s: 40, tier: 'watch',
  x: 0, w: 0, k: 0, ai: 0, c: [], r: [], cv: null, e: null, kd: null, b: null, ...o,
});
const sig = (kind: WakeSignal['kind'], at: string, label: string, first_seen = false): WakeSignal => ({ kind, at, first_seen, label, source: 'kev', url: null });
const item = (id: string, signals: WakeSignal[], o: Partial<Row> = {}): WokeItem => ({ id, at: signals[signals.length - 1].at, signals, row: row(id, o) });

const a = item('CVE-2021-0001', [sig('poc', '2026-10-12T08:00:00Z', 'first PoC repo on GitHub (unverified)'), sig('kev', '2026-10-30', 'added to CISA KEV')], { tier: 'exploited', x: 1 });
const b = item('CVE-2021-0002', [sig('metasploit', '2026-11-02T10:00:00Z', 'first Metasploit module', true)], { tier: 'likely', w: 1 });
const c = item('CVE-2021-0003', [sig('poc', '2026-10-06T00:00:00Z', 'first PoC repo on GitHub (unverified)')]);

describe('woke helpers', () => {
  it('writes the CVE page sentence', () => {
    expect(wakeSentence(a, 2026)).toBe('Woke up Oct 12: first PoC repo on GitHub (unverified). Oct 30: added to CISA KEV.');
    expect(wakeSentence(b, 2026)).toBe('Woke up Nov 2: first Metasploit module.');
  });

  it('filters by kind and by age, and ranks the most urgent first', () => {
    expect(byKind([a, b, c], 'poc').map((i) => i.id)).toEqual(['CVE-2021-0001', 'CVE-2021-0003']);
    expect(byKind([a, b, c], null)).toHaveLength(3);
    const now = Date.parse('2026-11-03T04:30:00Z');
    expect(wokeWithin([a, b, c], now, 7).map((i) => i.id)).toEqual(['CVE-2021-0001', 'CVE-2021-0002']);
    expect(mostUrgent([b, c, a], (i) => i.row.tier).map((i) => i.id)).toEqual(['CVE-2021-0001', 'CVE-2021-0002', 'CVE-2021-0003']);
    expect(isWakeKind('epss')).toBe(true);
    expect(isWakeKind('nonsense')).toBe(false);
  });

  it('groups by the Monday of the newest signal', () => {
    expect(weekOf('2026-11-02T10:00:00Z')).toBe('2026-11-02');
    expect(weekOf('2026-11-01')).toBe('2026-10-26');
    expect(byWeek([b, a, c]).map(([w, list]) => [w, list.map((i) => i.id)])).toEqual([
      ['2026-11-02', ['CVE-2021-0002']],
      ['2026-10-26', ['CVE-2021-0001']],
      ['2026-10-05', ['CVE-2021-0003']],
    ]);
  });

  it('explains first-seen dates and what is tracked', () => {
    expect(firstSeenTip(b.signals[0])).toMatch(/no date/);
    expect(firstSeenTip(a.signals[1])).toBeUndefined();
    expect(trackingNote({ metasploit: '2026-11-03T02:30:00Z', nuclei: '2026-11-03T02:30:00Z', epss: null })).toEqual({
      since: '2026-11-03T02:30:00Z',
      tracked: ['Metasploit modules', 'Nuclei templates'],
      untracked: ['EPSS jumps'],
    });
    expect(listing(['a', 'b', 'c'])).toBe('a, b and c');
  });
});
