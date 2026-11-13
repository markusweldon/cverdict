import { describe, expect, it } from 'vitest';
import { KNOB_DEFAULT, KNOB_MAX, KNOB_MIN, WATCH_FLOOR, tierFor, type Family, type Reason } from '../../../shared/contract';
import { BASE_POINTS, CHIPS, COLD_START_DAYS, EXPLOITED_FLOOR, chip } from '../../../shared/model';
import { buildKevPrior, kevVendorKey, orderReasons, vendorTokens } from '../../src/score';
import type { NormalizedCve, ScoredCve } from '../../src/types';
import {
  NOW,
  cvss,
  dateAgo,
  daysAgo,
  edb,
  makeCve,
  makeKev,
  makeKevCatalog,
  msf,
  nucleiTemplate,
  repo,
  score,
  ssvc,
} from '../fixtures/model/builders';

const ID = 'CVE-2026-100001';

const byId = (s: ScoredCve, id: string): Reason | undefined => s.reasons.find((r) => r.id === id);
const ids = (s: ScoredCve) => s.reasons.map((r) => r.id);
const pointsOf = (s: ScoredCve, id: string) => byId(s, id)?.points;
const familyPoints = (s: ScoredCve, f: Family) => s.reasons.filter((r) => r.family === f).reduce((a, r) => a + r.points, 0);
const total = (s: ScoredCve) => BASE_POINTS + s.reasons.reduce((a, r) => a + r.points, 0);

describe('baseline', () => {
  it('is quiet with the expected chips and arithmetic', () => {
    const s = score(makeCve());
    expect(ids(s)).toEqual(['x.none', 'sev.high', 'prior.none', 'ssvc.missing']);
    expect(s.raw).toBe(15 - 14 + 1 - 6);
    expect(s.score).toBe(0);
    expect(s.tier).toBe('quiet');
    expect(s.exploited).toBe(false);
    expect(s.weaponized).toBe(false);
    expect(byId(s, 'x.none')!.label).toBe('No public exploit after 20 days · no EPSS score');
    expect(byId(s, 'sev.high')!.label).toBe('High 7.5 · network (v3.1)');
    expect(byId(s, 'prior.none')!.label).toBe('Never in KEV: Acme');
  });

  it('copies polarity, family and source from the chip catalogue', () => {
    const s = score(makeCve());
    for (const r of s.reasons) {
      const def = chip(r.id);
      expect(r.family).toBe(def.family);
      expect(r.polarity).toBe(def.polarity);
    }
  });
});

describe('E family (confirmed exploitation)', () => {
  it('kev.listed: catalog entry, dated label, exploited tier, floor', () => {
    const s = score(makeCve(), { kev: [makeKev(ID, { dateAdded: '2026-10-21', dueDate: '2026-10-24' })] });
    const kev = byId(s, 'kev.listed')!;
    expect(kev.label).toBe('CISA KEV · added Oct 21 · due Oct 24');
    expect(kev.source).toBe('kev');
    expect(kev.at).toBe('2026-10-21');
    expect(kev.url).toContain(ID);
    expect(s.tier).toBe('exploited');
    expect(s.exploited).toBe(true);
    expect(s.raw).toBe(-4);
    expect(s.score).toBe(EXPLOITED_FLOOR);
    expect(kev.points).toBe(EXPLOITED_FLOOR - s.raw);
    expect(total(s)).toBe(s.score);
    expect(s.kev).toMatchObject({ date_added: '2026-10-21', due_date: '2026-10-24', forensic_triage: false });
  });

  it('kev.listed: falls back to the CISA-ADP KEV block in the CVE record', () => {
    const s = score(makeCve({ adpKev: { dateAdded: '2026-10-20', reference: 'https://www.cisa.gov/kev/x' } }));
    const kev = byId(s, 'kev.listed')!;
    expect(kev.label).toBe('CISA KEV · added Oct 20 (per CVE record)');
    expect(kev.source).toBe('cisa-adp');
    expect(kev.url).toBe('https://www.cisa.gov/kev/x');
    expect(s.tier).toBe('exploited');
    expect(s.kev).toBeNull();
  });

  it('ssvc.active', () => {
    const s = score(makeCve({ ssvc: ssvc('active', 'yes', 'total', '2026-10-22T10:00:00Z') }));
    expect(byId(s, 'ssvc.active')!.label).toBe('CISA SSVC: exploitation active · Oct 22');
    expect(s.tier).toBe('exploited');
  });

  it('vendor.exploited fires for CVSS v4 E:A', () => {
    const s = score(makeCve({ cnaExploitMaturity: ['A'] }));
    expect(byId(s, 'vendor.exploited')!.label).toBe('Vendor CVSS: exploitation reported (E:A)');
    expect(s.tier).toBe('exploited');
  });

  it.each([['U'], ['X'], ['P'], ['F'], ['H']])('vendor.exploited does not fire for E:%s', (e) => {
    expect(byId(score(makeCve({ cnaExploitMaturity: [e] })), 'vendor.exploited')).toBeUndefined();
  });

  it('relies on cnaExploitMaturity only (VulDB vectors are filtered upstream)', () => {
    const vuldb = makeCve({ cna: 'VulDB', cnaExploitMaturity: [], cvssMetrics: { ...cvss(7.5).cvssMetrics, E: 'P' } });
    const s = score(vuldb);
    expect(byId(s, 'vendor.poc')).toBeUndefined();
    expect(byId(s, 'vendor.exploited')).toBeUndefined();
  });

  it('vendor.itw', () => {
    const s = score(makeCve({ vendorInTheWild: true, cna: 'apple' }));
    expect(byId(s, 'vendor.itw')!.label).toBe('apple says exploited in the wild · Oct 6');
    expect(s.tier).toBe('exploited');
  });

  it('only the first E chip carries points; the rest are kept with 0', () => {
    const s = score(makeCve({ vendorInTheWild: true, cnaExploitMaturity: ['A'], ssvc: ssvc('active', 'no', 'partial') }), {
      kev: [makeKev(ID)],
    });
    const e = s.reasons.filter((r) => r.family === 'E');
    expect(e.map((r) => r.id)).toEqual(['kev.listed', 'ssvc.active', 'vendor.exploited', 'vendor.itw']);
    expect(e.slice(1).every((r) => r.points === 0)).toBe(true);
    expect(e[0].points).toBeGreaterThan(0);
    expect(total(s)).toBe(s.score);
  });

  it('adds the exploited bonus on top of the raw score (above the floor)', () => {
    // raw = 15 + vendor.poc 10 + sev.high 1 + prior.none −6 = 20 → 20 + 75 = 95
    const s = score(makeCve({ vendorInTheWild: true, cnaExploitMaturity: ['P'] }));
    expect(s.raw).toBe(20);
    expect(s.score).toBe(95);
    expect(pointsOf(s, 'vendor.itw')).toBe(75);
    expect(total(s)).toBe(95);
  });

  it('caps at 100', () => {
    const s = score(makeCve({ ...cvss(9.8), ssvc: ssvc('active', 'yes', 'total') }), {
      metasploit: { [ID]: [msf('exploit/multi/http/acme_rce')] },
    });
    expect(s.raw).toBe(15 + 34 + 13 + 14 - 6);
    expect(s.score).toBe(100);
    expect(total(s)).toBe(100);
  });

  it('ransomware Known adds 5 (exploited only), still capped at 100', () => {
    const s = score(makeCve(), { kev: [makeKev(ID, { knownRansomwareCampaignUse: 'Known' })] });
    expect(s.score).toBe(EXPLOITED_FLOOR + 5);
    expect(pointsOf(s, 'kev.ransomware')).toBe(5);
    expect(ids(s).slice(0, 2)).toEqual(['kev.listed', 'kev.ransomware']);
    expect(total(s)).toBe(s.score);

    const capped = score(makeCve({ ...cvss(9.8), ssvc: ssvc('active', 'yes', 'total') }), {
      kev: [makeKev(ID, { knownRansomwareCampaignUse: 'Known' })],
      metasploit: { [ID]: [msf('exploit/multi/http/acme_rce')] },
    });
    expect(capped.score).toBe(100);
    expect(pointsOf(capped, 'kev.ransomware')).toBe(0);
    expect(byId(score(makeCve(), { kev: [makeKev(ID)] }), 'kev.ransomware')).toBeUndefined();
  });
});

describe('X family (exploit artifacts and prediction)', () => {
  const cases: [string, Parameters<typeof score>[1], number, string][] = [
    ['x.metasploit', { metasploit: { [ID]: [msf('exploit/linux/http/acme_widget_rce', 600)] } }, 34, 'Metasploit: exploit/linux/http/acme_widget_rce (excellent)'],
    ['x.nuclei', { nuclei: { [ID]: [nucleiTemplate(ID)] } }, 30, 'Nuclei template (http · critical): scannable at scale'],
    ['x.exploitdb', { exploitdb: { [ID]: [edb('52012', '2026-10-10', true)] } }, 28, 'Exploit-DB 52012 (verified) · Oct 10'],
    ['epss.high', { epss: { [ID]: [0.142, 0.991] } }, 27, 'EPSS 14.2% · 99th pct'],
    ['x.poc', { poc: { [ID]: [repo(daysAgo(10))] } }, 20, '1 PoC repo (1 vetted), unverified, may be malware'],
    ['epss.mid', { epss: { [ID]: [0.031, 0.912] } }, 8, 'EPSS 3.1% · 91st pct'],
  ];

  it.each(cases)('%s fires with its catalogue points and a specific label', (id, spec, points, label) => {
    const s = score(makeCve(), spec);
    expect(byId(s, id)).toMatchObject({ points, label });
    expect(points).toBe(chip(id).points);
    expect(byId(s, 'x.none')).toBeUndefined();
    expect(familyPoints(s, 'X')).toBe(points);
  });

  it.each([['F'], ['H']])('vendor.functional for CVSS v3 E:%s: weaponization, not exploitation', (e) => {
    // Fortinet's CVE-2026-106170 shape: v3 E:F, SSVC exploitation none.
    const s = score(makeCve({ cnaExploitMaturity: [e], ssvc: ssvc('none', 'no', 'partial') }));
    expect(byId(s, 'vendor.functional')).toMatchObject({ points: 24, family: 'X', label: `Vendor CVSS: working exploit code exists (E:${e})` });
    expect(s.exploited).toBe(false);
    expect(s.tier).not.toBe('exploited');
    expect(s.raw).toBe(15 + 24 + 1 - 8 - 6);
    expect(s.score).toBe(s.raw);
  });

  it('vendor.functional outranks vendor.poc; both values listed once', () => {
    const s = score(makeCve({ cnaExploitMaturity: ['F', 'P', 'H'] }));
    const x = s.reasons.filter((r) => r.family === 'X');
    expect(x.map((r) => [r.id, r.points])).toEqual([
      ['vendor.functional', 24],
      ['vendor.poc', 0],
    ]);
    expect(x[0].label).toBe('Vendor CVSS: working exploit code exists (E:F, E:H)');
  });

  it('ssvc.poc and vendor.poc', () => {
    const s1 = score(makeCve({ ssvc: ssvc('poc', 'no', 'partial', '2026-10-07T12:00:00Z') }));
    expect(byId(s1, 'ssvc.poc')).toMatchObject({ points: 10, label: 'CISA SSVC: public PoC · Oct 7' });
    const s2 = score(makeCve({ cnaExploitMaturity: ['P'] }));
    expect(byId(s2, 'vendor.poc')).toMatchObject({ points: 10, label: 'Vendor CVSS: proof of concept exists (E:P)' });
  });

  it('takes the max within the family, winner first, losers kept with 0', () => {
    const s = score(makeCve({ cnaExploitMaturity: ['P'] }), {
      nuclei: { [ID]: [nucleiTemplate(ID)] },
      metasploit: { [ID]: [msf('auxiliary/scanner/http/acme_scan', 300, 'auxiliary'), msf('exploit/linux/http/acme_rce', 500)] },
      exploitdb: { [ID]: [edb('52012')] },
      poc: { [ID]: [repo(daysAgo(10))] },
      epss: { [ID]: [0.2, 0.99] },
    });
    const x = s.reasons.filter((r) => r.family === 'X');
    expect(x.map((r) => r.id)).toEqual(['x.metasploit', 'x.nuclei', 'x.exploitdb', 'epss.high', 'x.poc', 'vendor.poc']);
    expect(x.map((r) => r.points)).toEqual([34, 0, 0, 0, 0, 0]);
    // prefers exploit modules and higher ranks for the label
    expect(x[0].label).toBe('Metasploit: exploit/linux/http/acme_rce (great) +1 more');
  });

  it('weaponized (Metasploit or Nuclei) forces at least likely', () => {
    const s = score(makeCve({ ...cvss(5.0) }), { nuclei: { [ID]: [nucleiTemplate(ID, 'medium')] } });
    expect(s.score).toBeLessThan(KNOB_DEFAULT);
    expect(s.weaponized).toBe(true);
    expect(s.tier).toBe('likely');
    const notWeaponized = score(makeCve({ ...cvss(5.0) }), { exploitdb: { [ID]: [edb('52012')] } });
    expect(notWeaponized.weaponized).toBe(false);
    expect(notWeaponized.tier).not.toBe('likely');
  });

  it('x.none after the cold start when nothing fired and EPSS < 1%', () => {
    const s = score(makeCve(), { epss: { [ID]: [0.004, 0.6] } });
    expect(byId(s, 'x.none')).toMatchObject({ points: -14, label: 'No public exploit after 20 days · EPSS 0.4%' });
  });

  it('x.too_new before day 14 (unknown, 0 points)', () => {
    const s = score(makeCve({ published: daysAgo(3) }));
    expect(byId(s, 'x.too_new')).toMatchObject({ points: 0, polarity: 'unknown', label: 'Too new: day 3 of 14, exploit feeds lag' });
    expect(byId(s, 'x.none')).toBeUndefined();
    expect(s.unknowns).toContain('Exploit feeds have not caught up yet (day 3 of 14).');
  });

  it('exploit artifacts count during the cold start', () => {
    const s = score(makeCve({ published: daysAgo(2) }), { metasploit: { [ID]: [msf('exploit/x/y')] } });
    expect(pointsOf(s, 'x.metasploit')).toBe(34);
    expect(byId(s, 'x.too_new')).toBeUndefined();
  });
});

describe('EPSS cold start', () => {
  it('shows EPSS only as information before day 14', () => {
    const s = score(makeCve({ published: daysAgo(5) }), { epss: { [ID]: [0.5, 0.999] } });
    expect(byId(s, 'epss.high')).toBeUndefined();
    expect(byId(s, 'epss.mid')).toBeUndefined();
    expect(byId(s, 'epss.cold')).toMatchObject({ points: 0, polarity: 'info', label: 'EPSS 50.0% · 99th pct · day 5, too new to trust' });
    expect(byId(s, 'x.too_new')).toBeDefined();
    expect(s.epss).toMatchObject({ score: 0.5, percentile: 0.999, model: 'v2026.06.15' });
    expect(s.unknowns).toContain('EPSS is not trusted until day 14; this CVE is on day 5.');
  });

  it('trusts EPSS from day 14', () => {
    const s = score(makeCve({ published: daysAgo(COLD_START_DAYS) }), { epss: { [ID]: [0.5, 0.999] } });
    expect(pointsOf(s, 'epss.high')).toBe(27);
    expect(byId(s, 'epss.cold')).toBeUndefined();
  });

  it('no epss.cold chip when the CVE is not scored', () => {
    const s = score(makeCve({ published: daysAgo(1) }));
    expect(byId(s, 'epss.cold')).toBeUndefined();
    expect(s.unknowns).toContain('No EPSS score yet.');
  });
});

describe('PoC vetting', () => {
  it('drops forks', () => {
    const s = score(makeCve(), { poc: { [ID]: [repo(daysAgo(10), 50, true)] } });
    expect(s.exploits.poc.count).toBe(0);
    expect(byId(s, 'x.poc')).toBeUndefined();
    expect(byId(s, 'poc.unvetted')).toBeUndefined();
  });

  it('brand-new unstarred repos are unvetted (info only) and leave X unsettled, not "no exploit"', () => {
    const s = score(makeCve({ cna: 'Wordfence' }), { poc: { [ID]: [repo(daysAgo(1)), repo(daysAgo(2), 1)] } });
    expect(byId(s, 'x.poc')).toBeUndefined();
    expect(byId(s, 'poc.unvetted')).toMatchObject({ points: 0, label: '2 new PoC repos, unstarred and < 3 days old, not counted yet' });
    expect(byId(s, 'x.none')).toBeUndefined();
    expect(byId(s, 'x.too_new')).toMatchObject({ points: 0, polarity: 'unknown', label: 'Not settled: 2 PoC repos too new to vet' });
    expect(s.unknowns).toContain('A PoC repo appeared but is not vetted yet: it counts once it is 3 days old or has 2 stars.');
    // A PoC exists, so NOISE does not apply either.
    expect(pointsOf(s, 'noise.wordpress')).toBe(0);
    expect(s.raw).toBe(15 + 1 - 6);
    expect(s.exploits.poc).toMatchObject({ count: 2, vetted: 0, hype: false });
  });

  it('vetted by stars (≥ 2) or by age (≥ 3 days)', () => {
    expect(score(makeCve(), { poc: { [ID]: [repo(daysAgo(1), 2)] } }).exploits.poc.vetted).toBe(1);
    expect(score(makeCve(), { poc: { [ID]: [repo(daysAgo(3), 0)] } }).exploits.poc.vetted).toBe(1);
    const s = score(makeCve(), { poc: { [ID]: [repo(daysAgo(1)), repo(daysAgo(4), 0, false, 'b'), repo(daysAgo(1), 7, false, 'c')] } });
    expect(byId(s, 'x.poc')!.label).toBe('3 PoC repos (2 vetted), unverified, may be malware');
    expect(s.exploits.poc.top.map((r) => r.stars)).toEqual([7, 0, 0]);
  });

  it('flags hype when > 50 repos appear within 7 days of the first', () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => repo(daysAgo(12 - (i % 6)), i % 3, false, `r${i}`));
    const hype = score(makeCve(), { poc: { [ID]: many(51) } });
    expect(hype.exploits.poc.hype).toBe(true);
    expect(byId(hype, 'poc.hype')).toBeDefined();
    expect(pointsOf(hype, 'x.poc')).toBe(20);
    expect(hype.exploits.poc.top).toHaveLength(5);
    expect(score(makeCve(), { poc: { [ID]: many(50) } }).exploits.poc.hype).toBe(false);
  });
});

describe('SEV family', () => {
  it.each([
    [9.8, 'N', 'sev.crit_net', 13, 'Critical 9.8 · network (v3.1)'],
    [9.1, 'L', 'sev.crit', 6, 'Critical 9.1 · local (v3.1)'],
    [7.0, 'A', 'sev.high', 1, 'High 7.0 · adjacent (v3.1)'],
    [6.9, 'N', 'sev.low', -13, 'Medium 6.9 · network (v3.1)'],
    [3.1, 'P', 'sev.low', -13, 'Low 3.1 · physical (v3.1)'],
  ])('CVSS %s AV:%s → %s', (value, av, id, points, label) => {
    const s = score(makeCve({ ...cvss(value, av) }));
    expect(byId(s, id)).toMatchObject({ points, label, source: 'cvelist' });
    expect(s.reasons.filter((r) => r.family === 'SEV')).toHaveLength(1);
  });

  it('CVSS v4.0 is scored', () => {
    expect(byId(score(makeCve({ ...cvss(9.3, 'N', '4.0') })), 'sev.crit_net')!.label).toBe('Critical 9.3 · network (v4.0)');
  });

  it('sev.none when nobody scored it, or only CVSS v2 exists', () => {
    const none = score(makeCve({ cvss: null, cvssMetrics: {} }));
    expect(byId(none, 'sev.none')).toMatchObject({ points: 0, polarity: 'unknown' });
    expect(none.unknowns).toContain('No CVSS score from the CNA or CISA-ADP.');
    const v2 = score(makeCve({ ...cvss(10, 'N', '2.0') }));
    expect(byId(v2, 'sev.none')!.label).toBe('Only CVSS v2 (10.0), not scored');
  });

  it('CISA-ADP score: sev chip sourced from cisa-adp plus the sev.adp info chip', () => {
    const s = score(makeCve({ ...cvss(9.8, 'N', '3.1', 'cisa-adp') }));
    expect(byId(s, 'sev.crit_net')!.source).toBe('cisa-adp');
    expect(byId(s, 'sev.adp')).toMatchObject({ points: 0, label: 'No CNA score; CISA-ADP CVSS 9.8 used' });
  });
});

describe('SSVC family', () => {
  it('automatable and total add', () => {
    const s = score(makeCve({ ssvc: ssvc('none', 'yes', 'total') }));
    expect(s.reasons.filter((r) => r.family === 'SSVC').map((r) => [r.id, r.points])).toEqual([
      ['ssvc.total', 8],
      ['ssvc.automatable', 6],
    ]);
    expect(familyPoints(s, 'SSVC')).toBe(14);
  });

  it('not automatable and partial add', () => {
    const s = score(makeCve({ ssvc: ssvc('none', 'no', 'partial') }));
    expect(familyPoints(s, 'SSVC')).toBe(-8);
    expect(byId(s, 'ssvc.missing')).toBeUndefined();
  });

  it('ssvc.missing when CISA has not assessed it', () => {
    const s = score(makeCve());
    expect(byId(s, 'ssvc.missing')).toMatchObject({ points: 0, polarity: 'unknown' });
    expect(s.unknowns).toContain('No CISA SSVC assessment yet (exploitation, automatable, technical impact).');
  });
});

describe('PRIOR family', () => {
  it.each([
    ['Juniper Networks', ['juniper']],
    ['Oracle Corporation', ['oracle']],
    ['The Apache Software Foundation', ['apache']],
    ['QNAP Systems Inc.', ['qnap']],
    ['Palo Alto Networks, Inc.', ['palo', 'alto']],
    ['TP-Link Systems Inc.', ['tp', 'link']],
    ['MediaTek, Inc.', ['mediatek']],
    ['Soliton Systems K.K', ['soliton']],
    ['Hewlett Packard Enterprise (HPE)', ['hpe']],
    ['Zimbra', ['synacor']],
    ['Dassault Systèmes', ['dassault', 'systemes']],
    ['Systems', ['systems']],
    ['Café-Soft', ['cafe', 'soft']],
  ])('vendorTokens(%j) → %j', (name, tokens) => {
    expect(vendorTokens(name)).toEqual(tokens);
  });

  it('buildKevPrior indexes canonical vendors and vendor|product, named as CISA spells them', () => {
    const prior = buildKevPrior(
      makeKevCatalog([
        makeKev('CVE-2024-1'),
        makeKev('CVE-2024-2', { product: 'Gadget' }),
        makeKev('CVE-2024-3', { vendorProject: 'Palo Alto Networks', product: 'PAN-OS' }),
        makeKev('CVE-2024-4', { vendorProject: 'QNAP', product: 'QTS' }),
        makeKev('CVE-2024-5', { vendorProject: 'QNAP Systems', product: 'QTS' }),
        makeKev('CVE-2024-6', { vendorProject: 'QNAP', product: 'Photo Station' }),
        makeKev('CVE-2024-7', { vendorProject: 'Apache', product: 'Apache Tomcat' }),
        makeKev('CVE-2024-8', { vendorProject: 'n8n', product: 'n8n' }),
      ]),
    );
    expect([...prior.vendors.get('acme')!.ids]).toEqual(['CVE-2024-1', 'CVE-2024-2']);
    expect([...prior.products.get('acme|widget')!.ids]).toEqual(['CVE-2024-1']);
    expect(prior.products.has('paloalto|panos')).toBe(true);
    expect(prior.vendors.get('qnap')).toMatchObject({ name: 'QNAP', ids: new Set(['CVE-2024-4', 'CVE-2024-5', 'CVE-2024-6']) });
    expect(prior.products.get('qnap|qts')!.ids.size).toBe(2);
    // A leading vendor name is not part of the product key, nor said twice in the name.
    expect(prior.products.get('apache|tomcat')!.name).toBe('Apache Tomcat');
    expect(prior.products.get('n8n|n8n')!.name).toBe('n8n');
  });

  it('kevVendorKey: exact canonical match, else a whole-token prefix; never a substring', () => {
    const prior = buildKevPrior(
      makeKevCatalog([
        makeKev('CVE-2024-1', { vendorProject: 'Apple' }),
        makeKev('CVE-2024-2', { vendorProject: 'Siemens' }),
        makeKev('CVE-2024-3', { vendorProject: 'Rockwell' }),
        makeKev('CVE-2024-4', { vendorProject: 'Meta Platforms' }),
        makeKev('CVE-2024-5', { vendorProject: 'Meta' }),
      ]),
    );
    const key = (name: string) => kevVendorKey(vendorTokens(name), prior);
    expect(key('Apple Inc.')).toBe('apple');
    expect(key('Siemens AG')).toBe('siemens');
    expect(key('Siemens Mobility GmbH')).toBe('siemens');
    expect(key('Rockwell Automation')).toBe('rockwell');
    expect(key('Meta Platforms, Inc.')).toBe('metaplatforms');
    expect(key('Meta Platforms Reality Labs')).toBe('metaplatforms');
    expect(key('Applied Signal')).toBeNull();
    expect(key('Pineapple')).toBeNull();
    expect(key('Siemen')).toBeNull();
    expect(key('Rock')).toBeNull();
  });

  it('prior.product when other CVEs of the product are in KEV', () => {
    const s = score(makeCve(), { kev: [makeKev('CVE-2024-1'), makeKev('CVE-2024-2')] });
    expect(byId(s, 'prior.product')).toMatchObject({ points: 10, label: 'Product in KEV (×2): Acme Widget' });
  });

  it('prior.vendor when only other products of the vendor are in KEV (KEV spelling in the label)', () => {
    const s = score(makeCve({ affected: [{ vendor: 'ACME Corp.', product: 'Sprocket', purl: null }] }), { kev: [makeKev('CVE-2024-1')] });
    expect(byId(s, 'prior.vendor')).toMatchObject({ points: 8, label: 'Vendor in KEV (×1): Acme' });
    expect(byId(s, 'prior.vendor')!.url).toContain('search_api_fulltext=Acme');
  });

  it('matches CNA legal names to KEV short names (Juniper Networks / Junos OS, Oracle Corporation)', () => {
    const kev = [
      ...[1, 2, 3].map((i) => makeKev(`CVE-2024-${i}`, { vendorProject: 'Juniper', product: 'Junos OS' })),
      makeKev('CVE-2024-4', { vendorProject: 'Oracle', product: 'WebLogic Server' }),
      makeKev('CVE-2024-5', { vendorProject: 'Apache', product: 'Tomcat' }),
    ];
    const juniper = score(makeCve({ ...cvss(9.3, 'N', '4.0'), affected: [{ vendor: 'Juniper Networks', product: 'Junos OS', purl: null }] }), { kev });
    expect(byId(juniper, 'prior.product')).toMatchObject({ points: 10, label: 'Product in KEV (×3): Juniper Junos OS' });
    expect(byId(juniper, 'prior.none')).toBeUndefined();
    const oracle = score(makeCve({ affected: [{ vendor: 'Oracle Corporation', product: 'MySQL Server', purl: null }] }), { kev });
    expect(byId(oracle, 'prior.vendor')).toMatchObject({ points: 8, label: 'Vendor in KEV (×1): Oracle' });
    const tomcat = score(makeCve({ affected: [{ vendor: 'Apache Software Foundation', product: 'Apache Tomcat', purl: null }] }), { kev });
    expect(byId(tomcat, 'prior.product')!.label).toBe('Product in KEV (×1): Apache Tomcat');
    const qnap = score(makeCve({ affected: [{ vendor: 'QNAP Systems Inc.', product: 'QTS', purl: null }] }), {
      kev: [makeKev('CVE-2024-6', { vendorProject: 'QNAP', product: 'QTS' })],
    });
    expect(byId(qnap, 'prior.product')!.label).toBe('Product in KEV (×1): QNAP QTS');
  });

  it('no false positives across vendors that merely share letters', () => {
    const kev = [makeKev('CVE-2024-1', { vendorProject: 'Apple', product: 'iOS' }), makeKev('CVE-2024-2', { vendorProject: 'Arm', product: 'Mali' })];
    for (const vendor of ['Applied Signal', 'Armis', 'Pineapple Software', 'Charm Inc.']) {
      const s = score(makeCve({ affected: [{ vendor, product: 'iOS', purl: null }] }), { kev });
      expect(byId(s, 'prior.none')!.label).toBe(`Never in KEV: ${vendor}`);
    }
  });

  it('excludes the CVE itself', () => {
    const s = score(makeCve(), { kev: [makeKev(ID)] });
    expect(byId(s, 'prior.none')).toBeDefined();
    const withOther = score(makeCve(), { kev: [makeKev(ID), makeKev('CVE-2024-1')] });
    expect(byId(withOther, 'prior.product')!.label).toBe('Product in KEV (×1): Acme Widget');
  });

  it('matches a KEV CVE by its own KEV vendor/product too', () => {
    const s = score(makeCve({ affected: [] }), { kev: [makeKev(ID, { vendorProject: 'Zyxel', product: 'Firewall' }), makeKev('CVE-2024-9', { vendorProject: 'Zyxel', product: 'Firewall' })] });
    expect(byId(s, 'prior.product')!.label).toBe('Product in KEV (×1): Zyxel Firewall');
  });

  it('prior.unknown (0 points) and an unknown when no vendor is named', () => {
    const s = score(makeCve({ affected: [] }));
    expect(s.reasons.filter((r) => r.family === 'PRIOR')).toEqual([
      expect.objectContaining({ id: 'prior.unknown', points: 0, polarity: 'unknown', label: 'No affected vendor named, KEV history not checked' }),
    ]);
    expect(s.reasons.at(-1)!.polarity).toBe('unknown');
    expect(s.unknowns).toContain('No affected vendor is named, so KEV history could not be checked.');
    expect(s.raw).toBe(15 - 14 + 1);
  });
});

describe('unavailable sources are unknown, not absent', () => {
  it('KEV down: prior.unknown instead of prior.none, and the unknowns name it', () => {
    const s = score(makeCve(), { down: ['kev'] });
    expect(byId(s, 'prior.none')).toBeUndefined();
    expect(byId(s, 'prior.unknown')).toMatchObject({ points: 0, label: 'kev unavailable this run, KEV history not checked' });
    expect(s.raw).toBe(15 - 14 + 1);
    expect(s.unknowns).toContain('kev could not be loaded this run, so its evidence is unknown, not counted as absent.');
  });

  it('an exploit feed or EPSS down: no x.none, no NOISE; positive evidence from the others still counts', () => {
    const s = score(makeCve({ cna: 'Wordfence' }), { down: ['exploitdb', 'epss'] });
    expect(byId(s, 'x.none')).toBeUndefined();
    expect(byId(s, 'x.too_new')).toMatchObject({ points: 0, polarity: 'unknown', label: 'Exploit check incomplete: exploitdb, epss unavailable this run' });
    expect(pointsOf(s, 'noise.wordpress')).toBe(0);
    expect(s.raw).toBe(15 + 1 - 6);
    expect(s.unknowns).toContain('exploitdb and epss could not be loaded this run, so their evidence is unknown, not counted as absent.');
    expect(s.unknowns).not.toContain('No EPSS score yet.');

    const withPoc = score(makeCve(), { down: ['exploitdb'], poc: { [ID]: [repo(daysAgo(10))] } });
    expect(pointsOf(withPoc, 'x.poc')).toBe(20);
  });

  it('cold start keeps its own label and NOISE rule when feeds are down', () => {
    const s = score(makeCve({ published: daysAgo(3), cna: 'Wordfence' }), { down: ['metasploit'] });
    expect(byId(s, 'x.too_new')!.label).toBe('Too new: day 3 of 14, exploit feeds lag');
    expect(pointsOf(s, 'noise.wordpress')).toBe(0);
  });
});

describe('NOISE family', () => {
  it.each<[string, Partial<NormalizedCve>, number]>([
    ['noise.hobby', { noiseText: 'online shopping portal 1.0 by sourcecodester' }, -20],
    ['noise.disputed', { tags: ['disputed'] }, -15],
    ['noise.wordpress', { cna: 'Wordfence' }, -10],
    ['noise.wordpress', { noiseText: 'the acme gallery plugin for wordpress is vulnerable' }, -10],
    ['noise.kernel', { cna: 'Linux' }, -8],
  ])('%s fires', (id, o, points) => {
    const s = score(makeCve(o));
    expect(pointsOf(s, id)).toBe(points);
  });

  it('kernel noise needs technical impact ≠ total', () => {
    expect(byId(score(makeCve({ cna: 'Linux', ssvc: ssvc('none', 'no', 'total') })), 'noise.kernel')).toBeUndefined();
    expect(pointsOf(score(makeCve({ cna: 'Linux', ssvc: ssvc('none', 'no', 'partial') })), 'noise.kernel')).toBe(-8);
  });

  it('takes the minimum, losers kept with 0', () => {
    const s = score(makeCve({ cna: 'Wordfence', tags: ['disputed'], noiseText: 'sourcecodester wordpress plugin' }));
    const noise = s.reasons.filter((r) => r.family === 'NOISE');
    expect(noise.map((r) => [r.id, r.points])).toEqual([
      ['noise.hobby', -20],
      ['noise.disputed', 0],
      ['noise.wordpress', 0],
    ]);
    expect(byId(s, 'noise.hobby')!.label).toBe('Tutorial/hobby project (sourcecodester)');
  });

  it('applies when X is 0 (too new)', () => {
    expect(pointsOf(score(makeCve({ cna: 'Wordfence', published: daysAgo(2) })), 'noise.wordpress')).toBe(-10);
  });

  it('does not apply when X > 0', () => {
    const s = score(makeCve({ cna: 'Wordfence' }), { poc: { [ID]: [repo(daysAgo(10))] } });
    expect(pointsOf(s, 'noise.wordpress')).toBe(0);
    expect(familyPoints(s, 'NOISE')).toBe(0);
  });

  it('does not apply when exploited', () => {
    const s = score(makeCve({ cna: 'Wordfence', vendorInTheWild: true }));
    expect(pointsOf(s, 'noise.wordpress')).toBe(0);
  });
});

describe('INFO chips', () => {
  it('ai.credit, tag.eol', () => {
    const s = score(makeCve({ aiCredit: 'Claude Opus 5', tags: ['unsupported-when-assigned'] }));
    expect(byId(s, 'ai.credit')).toMatchObject({ points: 0, polarity: 'info', label: 'AI-credited: “Claude Opus 5”' });
    expect(byId(s, 'tag.eol')).toMatchObject({ points: 0 });
  });

  it('kev.due and kev.forensic', () => {
    const s = score(makeCve(), { kev: [makeKev(ID, { dueDate: '2026-10-29', forensicTriage: 'Yes' })] });
    expect(byId(s, 'kev.due')).toMatchObject({ points: 0, label: 'KEV due Oct 29 · in 3 days', at: '2026-10-29' });
    expect(byId(s, 'kev.forensic')).toBeDefined();
    expect(s.kev!.forensic_triage).toBe(true);
    const overdue = score(makeCve(), { kev: [makeKev(ID, { dueDate: '2026-10-24' })] });
    expect(byId(overdue, 'kev.due')!.label).toBe('KEV due Oct 24 · 2 days ago');
    expect(byId(overdue, 'kev.forensic')).toBeUndefined();
  });

  it('every emitted chip id exists in the catalogue and INFO chips carry 0 points', () => {
    const s = score(
      makeCve({ aiCredit: 'XBOW', tags: ['unsupported-when-assigned'], published: daysAgo(4), ...cvss(9.8, 'N', '3.1', 'cisa-adp') }),
      { kev: [makeKev(ID, { forensicTriage: 'Yes' })], epss: { [ID]: [0.2, 0.99] }, poc: { [ID]: [repo(daysAgo(1))] } },
    );
    const catalogue = new Set(CHIPS.map((c) => c.id));
    for (const r of s.reasons) {
      expect(catalogue.has(r.id)).toBe(true);
      if (r.family === 'INFO') expect(r.points).toBe(0);
    }
    expect(ids(s)).toEqual(expect.arrayContaining(['ai.credit', 'kev.due', 'kev.forensic', 'sev.adp', 'epss.cold', 'poc.unvetted', 'tag.eol']));
  });
});

describe('ordering and arithmetic', () => {
  const FAMILY_ORDER: Family[] = ['E', 'X', 'SEV', 'SSVC', 'PRIOR', 'NOISE', 'INFO'];
  const section = (r: Reason) => (r.polarity === 'unknown' ? 7 : FAMILY_ORDER.indexOf(r.family));

  it('orders reasons E, X, SEV, SSVC, PRIOR, NOISE, INFO, unknown', () => {
    const s = score(
      makeCve({ aiCredit: 'Big Sleep', vendorInTheWild: true, ssvc: ssvc('poc', 'yes', 'partial'), cna: 'Wordfence', published: daysAgo(6) }),
      { kev: [makeKev(ID), makeKev('CVE-2024-1')], exploitdb: { [ID]: [edb('1')] }, epss: { [ID]: [0.01, 0.5] } },
    );
    const sections = s.reasons.map(section);
    expect([...sections].sort((a, b) => a - b)).toEqual(sections);
    expect(s.reasons[0].id).toBe('kev.listed');
    const info = s.reasons.filter((r) => r.family === 'INFO').map((r) => r.id);
    expect(info).toEqual(['ai.credit', 'kev.due', 'epss.cold']);
  });

  it('orderReasons is stable inside a family', () => {
    const a: Reason = { id: 'x.nuclei', label: '', polarity: 'up', family: 'X', points: 30, source: 'nuclei' };
    const b: Reason = { ...a, id: 'x.metasploit', points: 0 };
    const unknown: Reason = { id: 'sev.none', label: '', polarity: 'unknown', family: 'SEV', points: 0, source: 'computed' };
    const info: Reason = { id: 'batch', label: '', polarity: 'info', family: 'INFO', points: 0, source: 'computed' };
    expect(orderReasons([unknown, info, a, b]).map((r) => r.id)).toEqual(['x.nuclei', 'x.metasploit', 'batch', 'sev.none']);
  });

  it('base + Σ points equals the score whenever no clamping happens', () => {
    const variants = [
      makeCve({ ...cvss(9.8), ssvc: ssvc('none', 'yes', 'total') }),
      makeCve({ cnaExploitMaturity: ['P'], tags: ['disputed'] }),
      makeCve({ published: daysAgo(1), ...cvss(8.8) }),
    ];
    for (const cve of variants) {
      const s = score(cve, { kev: [makeKev('CVE-2024-1')], poc: { [ID]: [repo(daysAgo(30))] } });
      expect(s.raw).toBeGreaterThanOrEqual(0);
      expect(total(s)).toBe(s.score);
    }
  });

  it('clamps non-exploited scores at 0 but keeps raw', () => {
    const s = score(makeCve({ ...cvss(4.3), noiseText: 'phpgurukul' }));
    expect(s.raw).toBe(15 - 14 - 13 - 6 - 20);
    expect(s.score).toBe(0);
  });
});

describe('tiers and the knob', () => {
  it('tierFor precedence', () => {
    expect(tierFor(10, true, false, 50)).toBe('exploited');
    expect(tierFor(10, false, true, 50)).toBe('likely');
    expect(tierFor(50, false, false, 50)).toBe('likely');
    expect(tierFor(49, false, false, 50)).toBe('watch');
    expect(tierFor(WATCH_FLOOR, false, false, 50)).toBe('watch');
    expect(tierFor(WATCH_FLOOR - 1, false, false, KNOB_MIN)).toBe('quiet');
    expect(tierFor(79, false, false, KNOB_MAX)).toBe('watch');
  });

  it('scoreCve applies the knob', () => {
    // raw = 15 + x.poc 20 + sev.high 1 + SSVC 14 − prior.none 6 = 44
    const cve = makeCve({ ssvc: ssvc('none', 'yes', 'total') });
    const spec = { poc: { [ID]: [repo(daysAgo(10))] } };
    expect(score(cve, spec).score).toBe(44);
    expect(score(cve, spec).tier).toBe('watch');
    expect(score(cve, spec, 40).tier).toBe('likely');
    expect(score(cve, spec, KNOB_MIN).tier).toBe('likely');
    expect(score(cve, spec, 45).tier).toBe('watch');
  });
});

describe('evidence timeline', () => {
  it('collects dated evidence, oldest first', () => {
    const s = score(
      makeCve({ ssvc: ssvc('active', 'yes', 'total', '2026-10-07T12:00:00Z') }),
      {
        kev: [makeKev(ID, { dateAdded: '2026-10-21', dueDate: '2026-11-11' })],
        epss: { [ID]: [0.3, 0.99] },
        poc: { [ID]: [repo('2026-10-12T08:00:00Z', 3), repo('2026-10-09T08:00:00Z', 1, true)] },
        exploitdb: { [ID]: [edb('52012', '2026-10-15')] },
      },
    );
    expect(s.timeline.map((e) => e.event)).toEqual([
      'CVE ID reserved',
      'Published by acme',
      'CISA SSVC assessment: exploitation active',
      'First PoC repo created on GitHub',
      'Exploit-DB 52012 published',
      'Added to CISA KEV',
      'EPSS scored 30.0%',
      'CISA KEV remediation due',
    ]);
    expect(s.timeline.find((e) => e.event === 'First PoC repo created on GitHub')!.at).toBe('2026-10-12T08:00:00Z');
    expect(s.timeline.map((e) => e.source)).toContain('poc-github');
  });

  it('omits a KEV due date in the past', () => {
    const s = score(makeCve(), { kev: [makeKev(ID, { dueDate: dateAgo(2) })] });
    expect(s.timeline.some((e) => e.event === 'CISA KEV remediation due')).toBe(false);
  });
});

describe('determinism', () => {
  it('same inputs → same output', () => {
    const cve = makeCve({ aiCredit: 'Claude' });
    const spec = { kev: [makeKev('CVE-2024-1')], epss: { [ID]: [0.05, 0.9] as [number, number] } };
    expect(score(cve, spec)).toEqual(score(cve, spec));
    expect(NOW.toISOString()).toBe('2026-10-26T19:30:00.000Z');
  });
});
