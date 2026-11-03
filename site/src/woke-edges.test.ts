import { describe, expect, it } from 'vitest';
import type { Row, WakeSignal, WokeItem } from '../../shared/contract';
import { byWeek, trackingNote, wakeSentence, weekOf, wokeWithin } from './woke';

const row = (id: string): Row => ({
  id, pub: '2021-03-01T00:00:00Z', cna: 'acme', v: 'Acme', p: 'Widget', t: 't', s: 40, tier: 'watch',
  x: 0, w: 0, k: 0, ai: 0, c: [], r: [], cv: null, e: null, kd: null, b: null,
});
const sig = (at: string, label = 'added to CISA KEV'): WakeSignal => ({ kind: 'kev', at, first_seen: false, label, source: 'kev', url: null });
const item = (id: string, ...ats: string[]): WokeItem => ({ id, at: ats[ats.length - 1], signals: ats.map((a) => sig(a)), row: row(id) });

describe('woke helpers at the edges', () => {
  it('puts Sunday night (UTC) in the week of the Monday before, also across a new year', () => {
    expect(weekOf('2026-11-08T23:59:59Z')).toBe('2026-11-02');
    expect(weekOf('2026-11-09T00:00:00Z')).toBe('2026-11-09');
    expect(weekOf('2026-01-01')).toBe('2025-12-29');
  });

  it('keeps the newest-first order inside a week', () => {
    const items = [item('CVE-2021-0003', '2026-11-04'), item('CVE-2021-0001', '2026-11-03'), item('CVE-2021-0002', '2026-11-03')];
    expect(byWeek(items).map(([w, list]) => [w, list.map((i) => i.id)])).toEqual([['2026-11-02', ['CVE-2021-0003', 'CVE-2021-0001', 'CVE-2021-0002']]]);
  });

  it('names the year when a signal is from another year', () => {
    expect(wakeSentence({ at: '2026-01-02', signals: [sig('2025-12-30'), sig('2026-01-02', 'first Nuclei template')] }, 2026)).toBe(
      'Woke up Dec 30, 2025: added to CISA KEV. Jan 2: first Nuclei template.',
    );
  });

  it('counts a wake exactly 7 days old as this week, and not one a minute older', () => {
    const now = Date.parse('2026-11-03T12:00:00Z');
    const items = [item('CVE-2021-0001', '2026-10-27T12:00:00Z'), item('CVE-2021-0002', '2026-10-27T11:59:00Z')];
    expect(wokeWithin(items, now, 7).map((i) => i.id)).toEqual(['CVE-2021-0001']);
  });

  it('reports the latest tracking start when the kinds started at different times', () => {
    expect(trackingNote({ metasploit: '2026-11-01T00:00:00Z', nuclei: '2026-11-03T02:30:00Z', epss: '2026-11-02T00:00:00Z' }).since).toBe('2026-11-03T02:30:00Z');
    expect(trackingNote({ metasploit: null, nuclei: null, epss: null })).toEqual({ since: null, tracked: [], untracked: ['Metasploit modules', 'Nuclei templates', 'EPSS jumps'] });
  });
});
