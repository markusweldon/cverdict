import { describe, expect, it } from 'vitest';
import { ROW_COLS, rowsFromTable, type Row } from '../../../shared/contract';
import { ATTRIBUTION } from '../../../shared/packages';
import { buildPackagesFile, packagesSummary } from '../../src/packages';
import { toRow } from '../../src/rows';
import { emptyOsvData, type OsvData, type OsvLite } from '../../src/sources/osv';
import { NOW, makeCve, makeEnrichment } from '../fixtures/model/builders';
import { scoreCve } from '../../src/score';

const enr = makeEnrichment();
const rowOf = (id: string): Row => toRow(scoreCve(makeCve({ id }), enr, { now: NOW, knob: 50 }));
const rows = new Map(['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003', 'CVE-2021-44228'].map((id) => [id, rowOf(id)]));

function osv(records: Partial<Record<'npm' | 'PyPI' | 'Maven', OsvLite[]>>, down: string[] = []): OsvData {
  const data = emptyOsvData('no copy');
  for (const [eco, recs] of Object.entries(records) as ['npm' | 'PyPI' | 'Maven', OsvLite[]][]) {
    data.mirror.ecosystems[eco] = { full_sync_at: NOW.toISOString(), zip_etag: null, cursor: '2026-10-26T00:00:00Z', fetched_at: NOW.toISOString(), records: recs };
    data.statuses[eco] = { ok: !down.includes(eco), stale: false, fetched_at: NOW.toISOString(), modified: '2026-10-26T00:00:00Z', advisories: recs.length, error: null };
  }
  return data;
}

const npm: OsvLite[] = [
  ['GHSA-aaaa-aaaa-aaaa', '2026-10-01T00:00:00Z', ['CVE-2026-1002', 'CVE-2026-1001', 'CVE-2015-0001'], [['lodash', [['>=0', '<4.17.21']]]]],
  ['GHSA-bbbb-bbbb-bbbb', '2026-10-01T00:00:00Z', ['CVE-2015-0002'], [['left-pad', [['>=0', '<2.0.0']]]]],
  ['GHSA-cccc-cccc-cccc', '2026-10-01T00:00:00Z', ['CVE-2026-1003'], [['__proto__', [['>=0', '<1.0.0']]], ['constructor', [['>=1.0.0']], ['0.9.9']]]],
];
const pypi: OsvLite[] = [
  // The same advisory lists Pillow and pillow: one key, merged ranges.
  ['PYSEC-2026-1', '2026-10-01T00:00:00Z', ['CVE-2026-1001'], [['Pillow', [['>=1.0', '<2.0']], ['0.9']], ['pillow', [['>=3.0', '<3.1'], ['>=1.0', '<2.0']], ['0.8']]]],
  ['GHSA-dddd-dddd-dddd', '2026-10-01T00:00:00Z', ['CVE-2026-1001'], [['pillow', [['>=1.0', '<2.0']]]]],
];

describe('buildPackagesFile', () => {
  it('keeps tracked CVEs only, one entry per package, CVE and advisory, sorted', () => {
    const f = buildPackagesFile(osv({ npm, PyPI: pypi }), rows, NOW.toISOString(), 30);
    expect(Object.keys(f.packages)).toEqual(['npm', 'PyPI']);
    expect(Object.keys(f.packages.npm!)).toEqual(['__proto__', 'constructor', 'lodash']);
    expect(f.packages.npm!.lodash).toEqual([
      ['CVE-2026-1001', 'GHSA-aaaa-aaaa-aaaa', [['>=0', '<4.17.21']]],
      ['CVE-2026-1002', 'GHSA-aaaa-aaaa-aaaa', [['>=0', '<4.17.21']]],
    ]);
    expect(f.packages.npm!.constructor).toEqual([['CVE-2026-1003', 'GHSA-cccc-cccc-cccc', [['>=1.0.0']], ['0.9.9']]]);
    expect(f.packages.PyPI).toEqual({
      pillow: [
        ['CVE-2026-1001', 'GHSA-dddd-dddd-dddd', [['>=1.0', '<2.0']]],
        ['CVE-2026-1001', 'PYSEC-2026-1', [['>=1.0', '<2.0'], ['>=3.0', '<3.1']], ['0.9', '0.8']],
      ],
    });
    expect(f.sources.find((s) => s.ecosystem === 'npm')).toMatchObject({ ok: true, advisories: 3, matched: 2 });
    expect(f.sources.find((s) => s.ecosystem === 'Go')).toMatchObject({ ok: false, advisories: 0, matched: 0, error: 'no copy' });
    expect(f.attribution).toEqual(ATTRIBUTION);
  });

  it('carries each CVE row exactly as toRow() makes it, in index.json columns', () => {
    const f = buildPackagesFile(osv({ npm }), rows, NOW.toISOString(), 30);
    expect(f.cves.cols).toEqual(ROW_COLS);
    expect(rowsFromTable(f.cves)).toEqual(['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003'].map((id) => rows.get(id)));
  });

  it('survives a JSON round trip with __proto__ and constructor as names', () => {
    const f = buildPackagesFile(osv({ npm }), rows, NOW.toISOString(), 30);
    const back = JSON.parse(JSON.stringify(f));
    expect(Object.hasOwn(back.packages.npm, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(back.packages.npm)).toBe(Object.prototype);
    expect(back.packages.npm.__proto__).toEqual([['CVE-2026-1003', 'GHSA-cccc-cccc-cccc', [['>=0', '<1.0.0']]]]);
  });

  it('is byte-stable whatever the order of the mirror records', () => {
    const a = JSON.stringify(buildPackagesFile(osv({ npm, PyPI: pypi }), rows, NOW.toISOString(), 30));
    const b = JSON.stringify(buildPackagesFile(osv({ npm: [...npm].reverse(), PyPI: [...pypi].reverse() }), rows, NOW.toISOString(), 30));
    expect(b).toBe(a);
  });

  it('publishes no packages for an ecosystem without a usable copy', () => {
    const f = buildPackagesFile(osv({ npm, PyPI: pypi }, ['PyPI']), rows, NOW.toISOString(), 30);
    expect(Object.keys(f.packages)).toEqual(['npm']);
    expect(f.sources.find((s) => s.ecosystem === 'PyPI')).toMatchObject({ ok: false, matched: 0 });
    expect(packagesSummary(f)).toEqual({ packages: 3, cves: 3, byEcosystem: [{ ecosystem: 'npm', packages: 3, cves: 3 }] });
  });
});
