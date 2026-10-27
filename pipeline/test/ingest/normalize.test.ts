import { describe, expect, it } from 'vitest';
import { cisaAdpFlags, findAiCredit, mentionsInTheWild, normalizeCve, parseCvssVector, readCveMeta } from '../../src/normalize';
import type { NormalizedCve } from '../../src/types';
import { fixtureRecord } from './helpers';

function normalize(record: unknown, inWindow = true): NormalizedCve {
  const meta = readCveMeta(record);
  if (!meta) throw new Error('fixture has no valid cveMetadata');
  const cve = normalizeCve(record, meta, inWindow);
  if (!cve) throw new Error(`fixture ${meta.id} is not PUBLISHED`);
  return cve;
}

const fixture = (id: string) => normalize(fixtureRecord(id));

/** A minimal PUBLISHED record; `cna`/`adp` override the containers. */
function record(cna: Record<string, unknown> | undefined, adp?: unknown[], meta: Record<string, unknown> = {}) {
  return {
    dataType: 'CVE_RECORD',
    cveMetadata: { cveId: 'CVE-2026-1234567', state: 'PUBLISHED', assignerShortName: 'example', datePublished: '2026-10-20T10:00:00Z', ...meta },
    containers: { ...(cna ? { cna } : {}), ...(adp ? { adp } : {}) },
  };
}

const cisaAdp = (metrics: unknown[]) => ({ providerMetadata: { shortName: 'CISA-ADP' }, metrics });

describe('normalizeCve on real records', () => {
  it('VulDB: ignores its E:P stamp, prefers CVSS v4.0, reads CISA-ADP SSVC', () => {
    const cve = fixture('CVE-2026-100878');
    expect(cve.cna).toBe('VulDB');
    expect(cve.cvss).toEqual({
      version: '4.0',
      score: 5.3,
      severity: 'MEDIUM',
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P',
      source: 'cna',
    });
    expect(cve.cvssMetrics.E).toBe('P');
    expect(cve.cnaExploitMaturity).toEqual([]);
    expect(cve.ssvc).toEqual({ exploitation: 'poc', automatable: 'no', technical_impact: 'partial', version: '2.0.3', timestamp: '2026-09-28T13:01:58.831Z' });
    expect(cve.cwe).toEqual(['CWE-639', 'CWE-285']);
    expect(cve.aiCredit).toBeNull();
  });

  it('Microsoft E:F: keeps exploit maturity, CISA-ADP SSVC active and the ADP KEV block', () => {
    const cve = fixture('CVE-2026-58644');
    expect(cve.cna).toBe('microsoft');
    expect(cve.cvss).toMatchObject({ version: '3.1', score: 9.8, severity: 'CRITICAL', source: 'cna' });
    expect(cve.cvssMetrics).toMatchObject({ AV: 'N', PR: 'N', UI: 'N', E: 'F', RL: 'O' });
    expect(cve.cnaExploitMaturity).toEqual(['F']);
    expect(cve.ssvc).toMatchObject({ exploitation: 'active', automatable: 'yes', technical_impact: 'total' });
    expect(cve.adpKev).toEqual({ dateAdded: '2026-07-16', reference: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-58644' });
    expect(cve.affected[0]).toEqual({ vendor: 'Microsoft', product: 'Microsoft SharePoint Enterprise Server 2016', purl: null });
  });

  it('CVSS v4 E:A (Palo Alto) counts as CNA exploit maturity', () => {
    const cve = fixture('CVE-2026-0257');
    expect(cve.cvss).toMatchObject({ version: '4.0', score: 7.8, source: 'cna' });
    expect(cve.cnaExploitMaturity).toEqual(['A']);
    expect(cve.adpKev?.dateAdded).toBe('2026-05-29');
    // Other ADP containers (siemens-SADP) are ignored.
    expect(cve.ssvc?.exploitation).toBe('active');
  });

  it('missing CNA CVSS falls back to CISA-ADP v3.1 and flags it; OpenAI credit is detected', () => {
    const cve = fixture('CVE-2026-109733');
    expect(cve.cnaCvssMissing).toBe(true);
    expect(cve.cvss).toEqual({
      version: '3.1',
      score: 8.1,
      severity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
      source: 'cisa-adp',
    });
    expect(cve.cvssMetrics.AV).toBe('N');
    expect(cve.aiCredit).toBe('Amy Burnett of OpenAI');
    expect(cve.cwe).toEqual([]);
  });

  it('AI credit: Claude; a CNA-supplied SSVC block is ignored in favour of CISA-ADP', () => {
    const cve = fixture('CVE-2026-103664');
    expect(cve.aiCredit).toBe('Claude Opus 5.5 (1M context)');
    // The CNA (role "Supplier") says automatable=yes; CISA-ADP says no.
    expect(cve.ssvc).toMatchObject({ exploitation: 'none', automatable: 'no', technical_impact: 'partial' });
  });

  it('AI credit: a handle ending in -AI', () => {
    expect(fixture('CVE-2026-94220').aiCredit).toBe('MopMonk-AI');
  });

  it('XSS payloads in descriptions stay literal text', () => {
    const cve = fixture('CVE-2026-100174');
    expect(cve.title).toBe('Stored Cross-Site Scripting (XSS) in AIL Framework Tag Selector via Unescaped Tag Names');
    expect(cve.description).toContain('<img src=x onerror=alert(1)>');
    expect(cve.description.length).toBeLessThanOrEqual(1000);
    expect(cve.description).toMatch(/…$/);
    expect(cve.noiseText).toContain('onerror');
    expect(cve.noiseText).toBe(cve.noiseText.toLowerCase());
  });

  it('in-the-wild vendor text: positive, negated, and a positive followed by an unrelated negation', () => {
    expect(fixture('CVE-2026-110447').vendorInTheWild).toBe(true);
    // "…there is no evidence that this vulnerability has been exploited in the wild."
    expect(fixture('CVE-2026-45776').vendorInTheWild).toBe(false);
    // "…as exploited in the wild in May 2026. … you have not been hit with exploitation"
    expect(fixture('CVE-2026-48172').vendorInTheWild).toBe(true);
  });

  it('disputed mitre record: n/a affected entries are skipped, ADP CVSS used, tag kept', () => {
    const cve = fixture('CVE-2026-37106');
    expect(cve.tags).toEqual(['disputed']);
    expect(cve.affected).toEqual([]);
    expect(cve.title).toBeNull();
    expect(cve.cvss).toMatchObject({ score: 9.8, source: 'cisa-adp' });
    expect(cve.ssvc?.technical_impact).toBe('total');
  });

  it('keeps tags such as unsupported-when-assigned, and package URLs', () => {
    expect(fixture('CVE-2026-94216').tags).toEqual(['unsupported-when-assigned']);
    expect(fixture('CVE-2026-108706').affected).toEqual([{ vendor: 'elunez', product: 'eladmin', purl: 'pkg:github/elunez/eladmin' }]);
  });

  it('handles 7-digit IDs and old records without metrics or CISA-ADP', () => {
    const cve = fixture('CVE-2015-1000000');
    expect(cve.id).toBe('CVE-2015-1000000');
    expect(cve.cvss).toBeNull();
    expect(cve.ssvc).toBeNull();
    expect(cve.cnaCvssMissing).toBe(true);
    expect(cve.references).toEqual(['http://www.vapidlabs.com/advisory.php?v=138']);
  });

  it('REJECTED records are not normalised, but their metadata is readable', () => {
    const rec = fixtureRecord('CVE-2026-9324');
    const meta = readCveMeta(rec);
    expect(meta).toMatchObject({ id: 'CVE-2026-9324', state: 'REJECTED', published: null, assigner: 'VulnCheck' });
    expect(meta?.rejected?.toISOString()).toBe('2026-08-21T16:39:13.263Z');
    expect(meta && normalizeCve(rec, meta, true)).toBeNull();
  });

  it('cisaAdpFlags reports the container and the KEV block', () => {
    expect(cisaAdpFlags(fixtureRecord('CVE-2026-58644'))).toEqual({ present: true, kev: true });
    expect(cisaAdpFlags(fixtureRecord('CVE-2026-100878'))).toEqual({ present: true, kev: false });
    expect(cisaAdpFlags(fixtureRecord('CVE-2015-1000000'))).toEqual({ present: false, kev: false });
  });
});

describe('normalizeCve on tolerant edge cases', () => {
  it('survives missing containers and unknown fields', () => {
    const cve = normalize({ cveMetadata: { cveId: 'cve-2026-99999', state: 'published', datePublished: '2026-10-20T10:00:00' }, extra: { x: 1 } });
    expect(cve).toMatchObject({ id: 'CVE-2026-99999', cna: '', title: null, description: '', cvss: null, affected: [], references: [], tags: [] });
    expect(cve.published).toBe('2026-10-20T10:00:00.000Z');
  });

  it('rejects records without a valid ID or publish date', () => {
    expect(readCveMeta({ cveMetadata: { cveId: 'CVE-26-1' } })).toBeNull();
    expect(readCveMeta(null)).toBeNull();
    const meta = readCveMeta(record({}, undefined, { datePublished: 'soon' }));
    expect(meta && normalizeCve(record({}), meta, true)).toBeNull();
  });

  it('sanitises odd vendor strings, titles and caps affected/references', () => {
    const rlo = String.fromCharCode(0x202e);
    const cve = normalize(
      record({
        title: `  Evil${rlo} title\n\twith\u0007bell `,
        affected: [
          { vendor: 'N/A', product: 'n/a' },
          { vendor: ' Acme\nCorp ', product: 'Widget' },
          { vendor: 'acme corp', product: 'widget' },
          { packageName: 'left-pad', collectionURL: 'https://registry.npmjs.org', packageURL: 'pkg:npm/left-pad' },
          { vendor: 'n/a', product: 'Real Product', packageURL: 'javascript:alert(1)' },
          ...Array.from({ length: 20 }, (_, i) => ({ vendor: `v${i}`, product: `p${i}` })),
        ],
        references: [
          { url: 'javascript:alert(1)' },
          { url: 'https://example.com/a' },
          { url: 'https://example.com/a' },
          ...Array.from({ length: 20 }, (_, i) => ({ url: `https://example.com/${i}` })),
        ],
      }),
    );
    expect(cve.title).toBe('Evil title withbell');
    expect(cve.affected.slice(0, 3)).toEqual([
      { vendor: 'Acme Corp', product: 'Widget', purl: null },
      { vendor: '', product: 'left-pad', purl: 'pkg:npm/left-pad' },
      { vendor: '', product: 'Real Product', purl: null },
    ]);
    expect(cve.affected).toHaveLength(10);
    expect(cve.references).toHaveLength(10);
    expect(cve.references[0]).toBe('https://example.com/a');
  });

  it('picks the English description (any en-* tag), else the first one', () => {
    const descriptions = [
      { lang: 'fr', value: 'Une vulnérabilité' },
      { lang: 'EN-us', value: 'A vulnerability' },
    ];
    expect(normalize(record({ descriptions })).description).toBe('A vulnerability');
    expect(normalize(record({ descriptions: [descriptions[0]] })).description).toBe('Une vulnérabilité');
  });

  it('CVSS preference: CNA v3.0 over CISA-ADP; ADP v3.1 over a CNA v2-only score; v2 as last resort', () => {
    const v30 = { cvssV3_0: { baseScore: '7.5', baseSeverity: 'high', vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' } };
    const v2 = { cvssV2_0: { baseScore: 5, vectorString: 'AV:N/AC:L/Au:N/C:P/I:N/A:N' } };
    const adp = [cisaAdp([{ cvssV3_1: { baseScore: 9.1, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' } }])];

    const a = normalize(record({ metrics: [v2, v30] }, adp));
    expect(a.cvss).toMatchObject({ version: '3.0', score: 7.5, severity: 'HIGH', source: 'cna' });
    expect(a.cnaCvssMissing).toBe(false);

    const b = normalize(record({ metrics: [v2] }, adp));
    expect(b.cvss).toMatchObject({ version: '3.1', score: 9.1, source: 'cisa-adp' });
    expect(b.cnaCvssMissing).toBe(true);

    const c = normalize(record({ metrics: [v2] }));
    expect(c.cvss).toMatchObject({ version: '2.0', score: 5, source: 'cna' });
    expect(c.cvssMetrics).toEqual({ AV: 'N', AC: 'L', Au: 'N', C: 'P', I: 'N', A: 'N' });
  });

  it('skips CVSS entries with invalid scores; collects E from every CNA vector', () => {
    const metrics = [
      { cvssV4_0: { baseScore: 11, vectorString: 'CVSS:4.0/AV:N/E:A' } },
      { cvssV3_1: { baseScore: 6.1, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:H' } },
      { cvssV3_0: { baseScore: 6.1, vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:X' } },
    ];
    const cve = normalize(record({ metrics }));
    expect(cve.cvss).toMatchObject({ version: '3.1', score: 6.1 });
    expect(cve.cnaExploitMaturity).toEqual(['A', 'H']);
  });

  it('reads SSVC option keys loosely and the ADP KEV block without a reference', () => {
    const adp = [
      { providerMetadata: { shortName: 'other-ADP' }, metrics: [{ other: { type: 'ssvc', content: { options: [{ Exploitation: 'active' }] } } }] },
      cisaAdp([
        { other: { type: 'SSVC', content: { version: '2.0.3', options: [{ Exploitation: 'PoC' }, { technicalImpact: 'Total' }] } } },
        { other: { type: 'kev', content: { dateAdded: '2026-10-21T00:00:00Z' } } },
      ]),
    ];
    const cve = normalize(record({}, adp));
    expect(cve.ssvc).toEqual({ exploitation: 'poc', automatable: '', technical_impact: 'total', version: '2.0.3', timestamp: null });
    expect(cve.adpKev).toEqual({ dateAdded: '2026-10-21', reference: null });
  });

  it('extracts CWE ids from cweId or the description text', () => {
    const problemTypes = [
      { descriptions: [{ cweId: 'cwe-79' }, { description: 'CWE-89 SQL Injection' }, { description: 'Improper input' }] },
    ];
    expect(normalize(record({ problemTypes })).cwe).toEqual(['CWE-79', 'CWE-89']);
  });

  it('detects in-the-wild text beyond the stored 1,000-character description', () => {
    const value = `${'Padding sentence. '.repeat(80)}This vulnerability has been exploited in the wild.`;
    const cve = normalize(record({ descriptions: [{ lang: 'en', value }] }));
    expect(cve.description.length).toBeLessThanOrEqual(1000);
    expect(cve.vendorInTheWild).toBe(true);
    expect(cve.noiseText.length).toBeLessThanOrEqual(4096);
  });
});

describe('mentionsInTheWild', () => {
  it.each([
    ['Microsoft is aware that an exploit for CVE-2025-53770 exists in the wild.', true],
    ['Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack.', true],
    ['Google is aware of reports that an exploit exists.', true],
    ['This vulnerability was used in limited, targeted attacks.', true],
    ['The flaw is being actively exploited.', true],
    ['There is no evidence that this vulnerability has been exploited in the wild.', false],
    ['We are not aware of any attacks in the wild abusing this flaw.', false],
    ['Microsoft isn’t aware of exploitation in the wild at this time.', false],
    ["The vendor hasn't seen it exploited in the wild.", false],
    ['We are unaware of reports of exploitation.', false],
    ['A remote attacker can exploit this without authentication.', false],
  ])('%s → %s', (text, expected) => {
    expect(mentionsInTheWild(text)).toBe(expected);
  });
});

describe('findAiCredit', () => {
  const credit = (...values: string[]) => findAiCredit({ credits: values.map((value) => ({ lang: 'en', value })) });

  it('matches AI tools, labs and handles, returning the first matching credit', () => {
    expect(credit('Jane Doe', 'Big Sleep, Google')).toBe('Big Sleep, Google');
    expect(credit('Found with GPT-5')).toBe('Found with GPT-5');
    expect(credit('AI-assisted research by X')).toBe('AI-assisted research by X');
    expect(credit('zerotrail-ai')).toBe('zerotrail-ai');
    expect(credit('Bartłomiej Dmitruk (striga.ai)')).toBe('Bartłomiej Dmitruk (striga.ai)');
    expect(credit('XBOW')).toBe('XBOW');
  });

  it('does not match ordinary names and words', () => {
    expect(credit('Thai Nguyen', 'Mumbai CERT', 'Kai Chen', 'OpenAIRE project', 'Wang Mai')).toBeNull();
    expect(findAiCredit(null)).toBeNull();
  });

  it('a person named Claude and researchers of a company on a .ai domain are not AI credits', () => {
    expect(credit('Claude Ndanda (TrixX)', 'Jean-Claude Dupont')).toBeNull();
    expect(credit('Naveen Sunkavally (Horizon3.ai)', 'Zach Hanley (@hacks_zach) of Horizon3.ai', 'Jimi Sebree working with Horizon3.ai')).toBeNull();
    // …but the model names still count, as do other .ai handles in the same credit.
    expect(credit('Claude Opus 5', 'x')).toBe('Claude Opus 5');
    expect(credit('Claude Code')).toBe('Claude Code');
    expect(credit('Claude Agents')).toBe('Claude Agents');
    expect(credit('Claude 3.5 Sonnet')).toBe('Claude 3.5 Sonnet');
    expect(credit('Claude (Anthropic)')).toBe('Claude (Anthropic)');
    expect(credit('Claude')).toBe('Claude');
    expect(credit('Claude Ndanda with Claude Opus 5')).toBe('Claude Ndanda with Claude Opus 5');
    expect(credit('Jane Roe (Horizon3.ai) and striga.ai')).toBe('Jane Roe (Horizon3.ai) and striga.ai');
  });

  it('stores at most 80 characters around the match, so the matched term is always visible', () => {
    const out = credit(`Discovered by Claude, ${'and a very long list of collaborators '.repeat(5)}`);
    expect(out?.startsWith('Discovered by Claude')).toBe(true);
    expect(out?.length).toBeLessThanOrEqual(80);
    const late = credit(
      'Thanks to Thomas Pornin and Paul Bottinelli of Trail of Bits in collaboration with OpenAI for reporting this issue responsibly.',
    );
    expect(late).toContain('in collaboration with OpenAI');
    expect(late?.length).toBeLessThanOrEqual(80);
    expect(late?.startsWith('…')).toBe(true);
    const tail = credit(`${'Reported by a long list of people, '.repeat(4)}using GLM-5.1 from Z.ai`);
    expect(tail?.endsWith('from Z.ai')).toBe(true);
  });
});

describe('parseCvssVector', () => {
  it('parses v3, v4 and parenthesised v2 vectors, skipping junk', () => {
    expect(parseCvssVector('CVSS:3.1/AV:N/AC:L/E:F')).toEqual({ AV: 'N', AC: 'L', E: 'F' });
    expect(parseCvssVector('(AV:N/AC:L/Au:N)')).toEqual({ AV: 'N', AC: 'L', Au: 'N' });
    expect(parseCvssVector('CVSS:4.0/AV:N/U:Red/__proto__:x/bad/:N/E:')).toEqual({ AV: 'N', U: 'Red' });
  });
});
