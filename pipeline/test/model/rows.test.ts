import { describe, expect, it } from 'vitest';
import { ROW_COLS, type CveDetail, type Reason } from '../../../shared/contract';
import { SCORE_MODEL } from '../../../shared/model';
import { firedChipIds, toDetail, toRow, topChipIds } from '../../src/rows';
import { cvss, daysAgo, makeCve, makeKev, msf, repo, score, ssvc } from '../fixtures/model/builders';

const ID = 'CVE-2026-100001';

const r = (id: string, points: number, polarity: Reason['polarity'], family: Reason['family'] = 'X'): Reason => ({
  id,
  label: id,
  polarity,
  family,
  points,
  source: 'computed',
});

describe('topChipIds', () => {
  it('positive by points, then info, then negative; skips 0-point losers and unknowns', () => {
    const reasons = [
      r('kev.listed', 90, 'up', 'E'),
      r('vendor.itw', 0, 'up', 'E'),
      r('x.poc', 20, 'up'),
      r('sev.crit_net', 13, 'up', 'SEV'),
      r('prior.none', -6, 'down', 'PRIOR'),
      r('noise.wordpress', -10, 'down', 'NOISE'),
      r('ai.credit', 0, 'info', 'INFO'),
      r('batch', 0, 'info', 'INFO'),
      r('ssvc.missing', 0, 'unknown', 'SSVC'),
    ];
    expect(topChipIds(reasons)).toEqual(['kev.listed', 'x.poc', 'sev.crit_net', 'ai.credit']);
    expect(topChipIds(reasons, 9)).toEqual(['kev.listed', 'x.poc', 'sev.crit_net', 'ai.credit', 'batch', 'noise.wordpress', 'prior.none']);
  });
});

describe('firedChipIds', () => {
  it('every chip that fired, family losers and info chips included, unknowns left out', () => {
    const reasons = [
      r('kev.listed', 90, 'up', 'E'),
      r('vendor.itw', 0, 'up', 'E'),
      r('x.poc', 20, 'up'),
      r('x.exploitdb', 0, 'up'),
      r('prior.none', -6, 'down', 'PRIOR'),
      r('noise.wordpress', 0, 'down', 'NOISE'),
      r('batch', 0, 'info', 'INFO'),
      r('ssvc.missing', 0, 'unknown', 'SSVC'),
      r('x.too_new', 0, 'unknown'),
    ];
    expect(firedChipIds(reasons)).toEqual(['kev.listed', 'vendor.itw', 'x.poc', 'x.exploitdb', 'prior.none', 'noise.wordpress', 'batch']);
  });
});

describe('toRow', () => {
  it('maps a scored CVE to the compact row', () => {
    const s = score(makeCve({ ...cvss(9.8), ssvc: ssvc('active', 'yes', 'total'), aiCredit: 'Claude' }), {
      kev: [makeKev(ID, { dueDate: '2026-10-29' })],
      metasploit: { [ID]: [msf('exploit/linux/http/acme')] },
      epss: { [ID]: [0.42, 0.99] },
    });
    const row = toRow(s);
    expect(Object.keys(row).sort()).toEqual([...ROW_COLS].sort());
    expect(row).toMatchObject({
      id: ID,
      cna: 'acme',
      v: 'Acme',
      p: 'Widget',
      t: 'Acme Widget SQL injection in login form',
      s: 100,
      tier: 'exploited',
      x: 1,
      w: 1,
      k: 1,
      ai: 1,
      cv: 9.8,
      e: 0.42,
      kd: '2026-10-29',
      b: null,
    });
    expect(row.c).toEqual(['kev.listed', 'x.metasploit', 'sev.crit_net', 'ssvc.total']);
    // r also has the E and X chips that lost within their family, and the info chips.
    expect(row.r).toEqual(['kev.listed', 'ssvc.active', 'x.metasploit', 'epss.high', 'sev.crit_net', 'ssvc.total', 'ssvc.automatable', 'prior.none', 'ai.credit', 'kev.due']);
  });

  it('flags KEV from the CISA-ADP block and falls back to the description for the title', () => {
    const long = `${'Lorem ipsum dolor sit amet '.repeat(10)}end.`;
    const row = toRow(score(makeCve({ title: null, description: long, adpKev: { dateAdded: '2026-10-20', reference: null }, affected: [] })));
    expect(row.k).toBe(1);
    expect(row.kd).toBeNull();
    expect(row.v).toBe('');
    expect(row.p).toBe('');
    expect(Array.from(row.t).length).toBeLessThanOrEqual(160);
    expect(row.t.startsWith('Lorem ipsum')).toBe(true);
  });

  it('zero flags for a quiet CVE', () => {
    const row = toRow(score(makeCve()));
    expect(row).toMatchObject({ x: 0, w: 0, k: 0, ai: 0, e: null, kd: null, tier: 'quiet' });
    expect(row.c).toEqual(['sev.high', 'x.none', 'prior.none']);
    expect(row.r).toEqual(['x.none', 'sev.high', 'prior.none']);
  });
});

describe('toDetail', () => {
  it('has exactly the CveDetail fields and carries the scoring output', () => {
    const s = score(makeCve({ published: daysAgo(15) }), { poc: { [ID]: [repo(daysAgo(10), 5)] } });
    const d = toDetail(s);
    const keys: (keyof CveDetail)[] = [
      'id', 'state', 'published', 'reserved', 'updated', 'cna', 'title', 'description', 'cvss', 'cwe', 'affected', 'ssvc', 'kev',
      'epss', 'exploits', 'ai_credit', 'tags', 'batch', 'score', 'reasons', 'unknowns', 'timeline', 'references', 'woke',
    ];
    expect(Object.keys(d).sort()).toEqual([...keys].sort());
    expect(d.state).toBe('PUBLISHED');
    expect(d.score).toEqual({ value: s.score, tier: s.tier, raw: s.raw, model: SCORE_MODEL });
    expect(d.reasons).toBe(s.reasons);
    expect(d.exploits.poc).toMatchObject({ count: 1, vetted: 1, hype: false });
    expect(JSON.parse(JSON.stringify(d))).toEqual(d);
  });
});
