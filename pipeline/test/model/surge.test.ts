import { describe, expect, it } from 'vitest';
import { SCHEMA_VERSION, SURGE_TOP_CNAS, severityBand } from '../../../shared/contract';
import { recordCvssScore } from '../../src/normalize';
import { bumpBand } from '../../src/sources/cvelist';
import { buildStats, buildSurge } from '../../src/stats';
import type { History } from '../../src/types';
import { checkSurge } from '../../src/validate';
import { NOW, cvss, makeCve, makeKev, makeKevCatalog, score } from '../fixtures/model/builders';
import type { JsonObject } from '../../src/util/json';

/** A History with bands counted the way the cvelist pass does. */
function history(records: { month: string; cna: string; band: number }[]): History {
  const h: History = { published: new Map(), reserved: new Map(), rejected: new Map(), ai: new Map(), bands: new Map(), cnaBands: new Map(), totalRecords: records.length };
  for (const r of records) {
    h.published.set(r.month, (h.published.get(r.month) ?? 0) + 1);
    bumpBand(h.bands!, r.month, r.band);
    let byCna = h.cnaBands!.get(r.cna);
    if (!byCna) h.cnaBands!.set(r.cna, (byCna = new Map()));
    bumpBand(byCna, r.month, r.band);
  }
  return h;
}

const rec = (month: string, cna: string, band: number, n = 1) => Array.from({ length: n }, () => ({ month, cna, band }));

describe('severityBand', () => {
  it('follows the CVSS rating scale; no score or 0.0 is none', () => {
    expect([10, 9, 8.9, 7, 6.9, 4, 3.9, 0.1, 0, null, undefined, 11, NaN].map(severityBand)).toEqual([0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4]);
  });
});

describe('recordCvssScore', () => {
  const metric = (key: string, baseScore: number) => ({ [key]: { baseScore, vectorString: 'CVSS:3.1/AV:N' } });
  it('prefers the CNA v3/v4 score, then CISA-ADP, then CNA v2', () => {
    const rec = (cna: unknown[], adp: unknown[] = []) => ({ containers: { cna: { metrics: cna }, adp: [{ providerMetadata: { shortName: 'CISA-ADP' }, metrics: adp }] } });
    expect(recordCvssScore(rec([metric('cvssV2_0', 5), metric('cvssV3_1', 9.8)]))).toBe(9.8);
    expect(recordCvssScore(rec([metric('cvssV2_0', 5)], [metric('cvssV3_1', 7.5)]))).toBe(7.5);
    expect(recordCvssScore(rec([metric('cvssV2_0', 5)]))).toBe(5);
    expect(recordCvssScore(rec([]))).toBeNull();
    expect(recordCvssScore('not a record')).toBeNull();
  });
});

describe('buildSurge', () => {
  const h = history([...rec('1999-03', 'mitre', 4, 2), ...rec('2026-09', 'Wordfence', 1, 3), ...rec('2026-10', 'Wordfence', 2), ...rec('2026-10', 'Linux', 2, 2), ...rec('2026-10', 'Linux', 1, 2), ...rec('2026-10', 'nobody', 4), ...rec('2026-10', 'mitre', 0)]);
  const kev = [
    score(makeCve({ id: 'CVE-2026-1', published: '2026-10-02T00:00:00Z', cna: 'Linux', ...cvss(7.8) })),
    score(makeCve({ id: 'CVE-2026-2', published: '2026-10-05T00:00:00Z', cna: 'Linux', ...cvss(7.1) })),
    score(makeCve({ id: 'CVE-2026-3', published: '2026-10-07T00:00:00Z', cna: 'nobody', cvss: null })),
  ];
  const s = buildSurge(h, kev, NOW)!;
  const m = (k: string) => (Number(k.slice(0, 4)) - 1999) * 12 + Number(k.slice(5)) - 1;

  it('has the header and one band row per month since 1999, summing to the published count', () => {
    expect(s.schema_version).toBe(SCHEMA_VERSION);
    expect(s.generated_at).toBe(NOW.toISOString());
    expect(s.start).toBe('1999-01');
    expect(s.severity).toHaveLength(buildStats({ history: h, kev: makeKevCatalog(), window: [], windowStart: NOW, now: NOW }).monthly.length);
    expect(s.severity[m('1999-03')]).toEqual([0, 0, 0, 0, 2]);
    expect(s.severity[m('2026-10')]).toEqual([1, 2, 3, 0, 1]);
  });

  it('lists CNAs most first, trimmed to the months they have CVEs', () => {
    expect(s.cnas.map((c) => c.cna)).toEqual(['Linux', 'Wordfence', 'mitre', 'nobody']);
    const wf = s.cnas[1];
    expect(wf.from).toBe(m('2026-09'));
    expect(wf.severity).toEqual([
      [0, 3, 0, 0, 0],
      [0, 0, 1, 0, 0],
    ]);
    // mitre: 1999-03 to 2026-10, zeros in between kept.
    expect(s.cnas[2].from).toBe(m('1999-03'));
    expect(s.cnas[2].severity).toHaveLength(m('2026-10') - m('1999-03') + 1);
  });

  it('keeps only the top CNAs', () => {
    const many = history(Array.from({ length: SURGE_TOP_CNAS + 5 }, (_, i) => rec('2026-10', `cna${String(i).padStart(2, '0')}`, 2, i + 1)).flat());
    const t = buildSurge(many, [], NOW)!;
    expect(t.cnas).toHaveLength(SURGE_TOP_CNAS);
    expect(t.cnas[0].cna).toBe(`cna${SURGE_TOP_CNAS + 4}`);
  });

  it('counts KEV records by publication month, CNA index (or -1) and band', () => {
    expect(s.kev).toEqual([
      [m('2026-10'), 0, 1, 2],
      [m('2026-10'), 3, 4, 1],
    ]);
  });

  it('is null when the pass counted no bands (older history)', () => {
    expect(buildSurge({ published: new Map(), reserved: new Map(), rejected: new Map(), ai: new Map(), totalRecords: 0 }, [], NOW)).toBeNull();
  });

  describe('checkSurge', () => {
    const stats = buildStats({ history: h, kev: makeKevCatalog([makeKev('CVE-2026-1')]), window: [], windowStart: NOW, now: NOW }) as unknown as JsonObject;
    const check = (mut: (x: ReturnType<typeof structuredClone<typeof s>>) => void) => {
      const x = structuredClone(s);
      mut(x);
      const errors: string[] = [];
      checkSurge(x as unknown as JsonObject, stats, errors);
      return errors;
    };
    it('passes the built file, and a missing one', () => {
      expect(check(() => {})).toEqual([]);
      const errors: string[] = [];
      checkSurge(undefined, stats, errors);
      expect(errors).toEqual([]);
    });
    it('catches rows that disagree with stats.json, overlong CNAs, overfull bands and bad KEV cells', () => {
      expect(check((x) => (x.severity[m('2026-10')][0] = 5))[0]).toMatch(/sums to 11, stats.json monthly says 7/);
      expect(check((x) => x.severity.pop())[0]).toMatch(/severity has \d+ rows, expected/);
      expect(check((x) => (x.severity[3] = [1, 2]))[0]).toMatch(/not five whole counts/);
      expect(check((x) => (x.cnas[1].from = x.severity.length))[0]).toMatch(/does not fit/);
      expect(check((x) => (x.cnas[1].severity[1] = [0, 0, 9, 0, 0]))[0]).toMatch(/more than month/);
      expect(check((x) => x.cnas.push({ ...x.cnas[0] }))[0]).toMatch(/repeated name/);
      expect(check((x) => (x.kev = [x.kev[1], x.kev[0]]))[0]).toMatch(/not sorted/);
      expect(check((x) => (x.kev[0][3] = 3))[0]).toMatch(/more than its month/);
      expect(check((x) => (x.kev[0][1] = 7))[0]).toMatch(/bad cell/);
    });
    it('skips the sum check when stats.json is from another run', () => {
      const errors: string[] = [];
      const x = structuredClone(s);
      x.severity[m('2026-10')][0] = 5;
      checkSurge(x as unknown as JsonObject, { ...stats, generated_at: '2026-10-26T18:00:00.000Z' }, errors);
      expect(errors).toEqual([]);
    });
  });
});
