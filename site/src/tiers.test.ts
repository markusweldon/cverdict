import { describe, expect, it } from 'vitest';
import type { Reason } from '../../shared/contract';
import { BASE_POINTS, CHIPS, FAST_LANE } from '../../shared/model';
import { cvss, daysAgo, makeKev, makeCve, repo, score } from '../../pipeline/test/fixtures/model/builders';
import { GROUP_META, GROUP_ORDER, groupOf, groupReasons, lostNote } from './tiers';

const ID = 'CVE-2026-100001';
const fortios = [{ vendor: 'Fortinet', product: 'FortiOS', purl: null }];
const kev = [makeKev('CVE-2024-1', { vendorProject: 'Fortinet', product: 'FortiOS' })];
const total = (rs: readonly Reason[]) => BASE_POINTS + rs.reduce((a, r) => a + r.points, 0);

describe('display groups', () => {
  it('shows fast.lane and edge.device under Exposure, right after Exploit artifacts, and nothing else moves', () => {
    expect(GROUP_ORDER.slice(0, 3)).toEqual(['E', 'X', 'EXPOSURE']);
    expect(GROUP_META.EXPOSURE.label).toBe('Exposure');
    expect(CHIPS.filter((c) => groupOf(c) === 'EXPOSURE').map((c) => c.id)).toEqual(['fast.lane', 'edge.device']);
    for (const c of CHIPS) if (c.id !== 'fast.lane' && c.id !== 'edge.device') expect(groupOf(c)).toBe(c.family);
    // Every chip is in a group the page shows.
    for (const c of CHIPS) expect(GROUP_ORDER).toContain(groupOf(c));
  });

  it('groups a fast lane CVE without changing its scoring families or points', () => {
    const s = score(makeCve({ published: daysAgo(2), affected: fortios, ...cvss(9.8), ssvc: null }), { kev });
    const before = JSON.stringify(s.reasons);
    const groups = groupReasons(s.reasons);
    expect(JSON.stringify(s.reasons)).toBe(before);
    expect(s.score).toBe(50);
    const exposure = groups.find((g) => g.group === 'EXPOSURE')!;
    expect(exposure.items.map((i) => i.reason.id)).toEqual(['fast.lane', 'edge.device']);
    expect(exposure.pts).toBe(FAST_LANE);
    expect(exposure.scored).toBe(true);
    expect(exposure.items.every((i) => !i.lost)).toBe(true);
    // Scoring families are untouched: the fast lane is still X, the edge device still INFO.
    expect(s.reasons.find((r) => r.id === 'fast.lane')!.family).toBe('X');
    expect(s.reasons.find((r) => r.id === 'edge.device')!.family).toBe('INFO');
    expect(groups.find((g) => g.group === 'INFO')?.items.some((i) => i.reason.id === 'edge.device') ?? false).toBe(false);
    // The sections still add up to the score.
    const shown = groups.flatMap((g) => g.items.map((i) => i.reason));
    expect(BASE_POINTS + groups.reduce((a, g) => a + g.pts, 0)).toBe(total(s.reasons));
    expect(shown.length).toBe(s.reasons.filter((r) => r.polarity !== 'unknown').length);
  });

  it('keeps the fast lane listed under Exposure with 0 when a stronger exploit chip wins', () => {
    const s = score(makeCve({ published: daysAgo(3), affected: fortios, ...cvss(9.8), ssvc: null }), { kev, poc: { [ID]: [repo(daysAgo(10))] } });
    expect(s.reasons.find((r) => r.id === 'x.poc')!.points).toBe(20);
    const groups = groupReasons(s.reasons);
    const exposure = groups.find((g) => g.group === 'EXPOSURE')!;
    const lane = exposure.items.find((i) => i.reason.id === 'fast.lane')!;
    expect(lane.reason.points).toBe(0);
    expect(lane.lost).toBe(true);
    expect(lostNote(lane)).toBe('counted 0: a stronger exploit chip won');
    expect(exposure.pts).toBe(0);
    const x = groups.find((g) => g.group === 'X')!;
    expect(x.items.map((i) => i.reason.id)).toContain('x.poc');
    expect(x.items.map((i) => i.reason.id)).not.toContain('fast.lane');
    expect(x.pts).toBe(20);
  });

  it('names the fast lane when it beats a weaker exploit sign shown under Exploit artifacts', () => {
    const lane: Reason = { id: 'fast.lane', label: 'Fast lane', polarity: 'up', family: 'X', points: FAST_LANE, source: 'computed' };
    const poc: Reason = { id: 'ssvc.poc', label: 'CISA SSVC: public PoC', polarity: 'up', family: 'X', points: 0, source: 'cisa-adp' };
    const x = groupReasons([lane, poc]).find((g) => g.group === 'X')!;
    expect(lostNote(x.items[0])).toBe('counted 0: Fast lane under Exposure won');
    // A loser whose winner is in the same section keeps the usual note.
    const msf: Reason = { id: 'x.metasploit', label: 'Metasploit', polarity: 'up', family: 'X', points: 34, source: 'metasploit' };
    const same = groupReasons([msf, poc, { ...lane, points: 0 }]);
    expect(lostNote(same.find((g) => g.group === 'X')!.items[1])).toBe('counted 0: a stronger chip in this family won');
  });

  it('shows no points total for a section of information chips only', () => {
    const edge: Reason = { id: 'edge.device', label: 'Edge device: firewall', polarity: 'info', family: 'INFO', points: 0, source: 'computed' };
    expect(groupReasons([edge])).toEqual([{ group: 'EXPOSURE', pts: 0, scored: false, items: [{ reason: edge, lost: false }] }]);
  });
});
