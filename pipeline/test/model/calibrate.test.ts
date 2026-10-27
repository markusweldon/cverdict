import { describe, expect, it } from 'vitest';
import { calibrate, enrichmentOf, formatReport, hideExploitation, tierCounts } from '../../../scripts/calibrate';
import { scoreCve } from '../../src/score';
import { NOW, cohort, dateAgo, makeCve, makeEnrichment, makeIngest, makeKev, msf, ssvc } from '../fixtures/model/builders';

const ids = (reasons: { id: string; points: number }[]) => reasons.filter((r) => r.points !== 0).map((r) => r.id);

describe('hideExploitation', () => {
  const listed = makeCve({
    ssvc: ssvc('active', 'yes', 'total'),
    adpKev: { dateAdded: dateAgo(5), reference: null },
  });
  const spec = {
    kev: [makeKev(listed.id), makeKev('CVE-2025-1111', { dateAdded: '2025-03-01' })],
    epss: { [listed.id]: [0.5, 0.99] as [number, number] },
  };

  it('scores a KEV CVE without its KEV entry, the ADP KEV block, SSVC active and its EPSS', () => {
    const enr = makeEnrichment(spec);
    expect(scoreCve(listed, enr, { now: NOW }).exploited).toBe(true);

    const hidden = hideExploitation(listed, enr);
    const s = scoreCve(hidden.cve, hidden.enr, { now: NOW });
    expect(s.exploited).toBe(false);
    expect(hidden.cve.ssvc?.exploitation).toBe('none');
    // The other Acme Widget KEV entry still counts; EPSS is gone, so after 14 days x.none fires.
    expect(ids(s.reasons)).toEqual(['x.none', 'sev.high', 'ssvc.total', 'ssvc.automatable', 'prior.product']);
    expect(s.reasons.find((r) => r.id === 'prior.product')?.label).toContain('(×1)');
    expect(s.score).toBe(15 - 14 + 1 + 8 + 6 + 10);
  });

  it('lowers SSVC active to poc when a public exploit artifact exists', () => {
    const enr = makeEnrichment({ ...spec, metasploit: { [listed.id]: [msf('exploit/multi/http/acme_widget_sqli')] } });
    expect(hideExploitation(listed, enr).cve.ssvc?.exploitation).toBe('poc');
  });

  it('keeps SSVC that was not active, and leaves the original enrichment alone', () => {
    const enr = makeEnrichment(spec);
    const poc = makeCve({ ssvc: ssvc('poc', 'no', 'partial') });
    expect(hideExploitation(poc, enr).cve.ssvc).toEqual(poc.ssvc);
    hideExploitation(listed, enr);
    expect(enr.kev.entries.has(listed.id)).toBe(true);
    expect(enr.epss.scores.has(listed.id)).toBe(true);
  });
});

describe('calibrate', () => {
  const batch = cohort(60, { startId: 300000 });
  const kevCve = makeCve({ id: 'CVE-2026-100001', ssvc: ssvc('active', 'no', 'partial') });
  const old = makeCve({ id: 'CVE-2021-44228', published: '2021-12-10T00:00:00.000Z', inWindow: false });
  const ing = makeIngest([...batch, kevCve, old], {
    kev: [
      makeKev(kevCve.id),
      makeKev(old.id, { dateAdded: '2021-12-10' }),
      makeKev('CVE-2026-999999', { dateAdded: dateAgo(3) }),
      makeKev('CVE-2026-888888', { dateAdded: dateAgo(-2) }),
    ],
  });
  const cal = calibrate({ ing, now: NOW, year: 2026, batchId: null });

  it('scores the window exactly as the pipeline does', () => {
    const enr = enrichmentOf(ing);
    expect(cal.window).toHaveLength(61);
    expect(tierCounts(cal.window, 50)).toEqual(tierCounts([...batch, kevCve].map((c) => scoreCve(c, enr, { now: NOW })), 50));
    expect(tierCounts(cal.window, 50).exploited).toBe(1);
  });

  it('re-scores only this year’s KEV additions up to now, and names those without a record', () => {
    expect(cal.kevAdds.map((s) => s.cve.id)).toEqual([kevCve.id]);
    expect(cal.kevAdds[0].exploited).toBe(false);
    expect(cal.kevMissing).toEqual(['CVE-2026-999999']);
    expect(cal.ssvcLowered).toEqual({ poc: 0, none: 1 });
  });

  it('breaks down the largest patch-day batch', () => {
    expect(cal.batch?.id).toBe('microsoft-2026-10-13');
    expect(cal.batchMembers).toHaveLength(60);
  });

  it('prints one Markdown row per knob for each table', () => {
    const md = formatReport(cal, { ing, now: NOW, year: 2026, batchId: null, windowDays: 30 });
    expect(md).toContain('## KEV recall without KEV: 1 CVEs added to KEV in 2026');
    expect(md).toContain('| **50** | 1 | 0 | 0 | 60 | 1 (1.6% · 1 in 61) |');
    expect(md).toContain('## Batch microsoft-2026-10-13: Microsoft · 2026-10-13 · 60 CVEs');
    expect(md.match(/^\| (\*\*)?\d\d(\*\*)? \|/gm)).toHaveLength(4 * 5);
  });
});
