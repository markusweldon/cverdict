import { describe, expect, it } from 'vitest';
import { ATTRIBUTION, advisoryDatabase, advisoryUrl, ecosystemOfPurlType, mergePackageFiles, packageKey, rangeText, rangesText } from './packages';
import { PACKAGE_ECOSYSTEMS, ROW_COLS, SCHEMA_VERSION, rowsFromTable, type PackagesFile } from './contract';

describe('packageKey', () => {
  it('normalises names per ecosystem', () => {
    expect(packageKey('PyPI', 'Apache_Airflow')).toBe('apache-airflow');
    expect(packageKey('PyPI', 'zope.interface')).toBe('zope-interface');
    expect(packageKey('PyPI', 'a-_.b')).toBe('a-b');
    expect(packageKey('crates.io', 'Serde_JSON')).toBe('serde-json');
    expect(packageKey('NuGet', 'Newtonsoft.Json')).toBe('newtonsoft.json');
    expect(packageKey('Packagist', 'Drupal/Core')).toBe('drupal/core');
    expect(packageKey('npm', '@Scope/Pkg')).toBe('@Scope/Pkg');
    expect(packageKey('Maven', 'org.apache.logging.log4j:log4j-core')).toBe('org.apache.logging.log4j:log4j-core');
    expect(packageKey('Go', 'github.com/Foo/Bar')).toBe('github.com/Foo/Bar');
  });
});

describe('ecosystemOfPurlType', () => {
  it('maps the eight purl types and nothing else', () => {
    expect(['npm', 'pypi', 'maven', 'golang', 'cargo', 'gem', 'composer', 'nuget', 'NPM'].map(ecosystemOfPurlType)).toEqual([
      'npm', 'PyPI', 'Maven', 'Go', 'crates.io', 'RubyGems', 'Packagist', 'NuGet', 'npm',
    ]);
    for (const t of ['deb', 'rpm', 'apk', 'github', 'constructor', '__proto__', 'toString']) expect(ecosystemOfPurlType(t), t).toBeNull();
  });
});

describe('advisory IDs', () => {
  it('links GHSA to GitHub and the rest to osv.dev, and malformed IDs nowhere', () => {
    expect(advisoryUrl('GHSA-jfh8-c2jp-5v3q')).toBe('https://github.com/advisories/GHSA-jfh8-c2jp-5v3q');
    expect(advisoryUrl('PYSEC-2021-19')).toBe('https://osv.dev/vulnerability/PYSEC-2021-19');
    expect(advisoryUrl('DRUPAL-CORE-2018-002')).toBe('https://osv.dev/vulnerability/DRUPAL-CORE-2018-002');
    for (const bad of ['ghsa-x', 'GHSA-', 'GHSA-../../x', 'javascript:alert(1)', 'GHSA-a b', `GHSA-${'a'.repeat(70)}`]) expect(advisoryUrl(bad), bad).toBeNull();
  });

  it('knows which database an ID belongs to, by its longest prefix', () => {
    expect(advisoryDatabase('GHSA-jfh8-c2jp-5v3q')?.name).toBe('GitHub Advisory Database');
    expect(advisoryDatabase('RUSTSEC-2023-0001')?.license).toMatch(/^CC0-1.0/);
    expect(advisoryDatabase('DRUPAL-CONTRIB-2024-001')?.notice).toContain('Copyright (c) 2025 Ackama');
    for (const other of ['OSV-2020-111', 'GSD-2021-1', 'EEF-CVE-2023-1', 'MAL-2024-1', 'GHSAX-1', 'DRUPAL-2018-1']) expect(advisoryDatabase(other), other).toBeNull();
  });

  it('lists every licence with its prefixes', () => {
    expect(ATTRIBUTION.flatMap((a) => a.prefixes)).toEqual(['GHSA', 'PYSEC', 'GO', 'RUSTSEC', 'DRUPAL-CORE', 'DRUPAL-CONTRIB']);
    expect(ATTRIBUTION.every((a) => a.license.length > 0 && a.url.startsWith('https://'))).toBe(true);
  });
});

describe('rangeText', () => {
  it('says each range in words', () => {
    expect(rangeText(['>=0', '<1.2.3'])).toBe('before 1.2.3');
    expect(rangeText(['>=1.0', '<1.2.3'])).toBe('from 1.0, before 1.2.3');
    expect(rangeText(['>=1.0', '<=1.4'])).toBe('from 1.0 up to 1.4, no fixed version listed');
    expect(rangeText(['>=1.0'])).toBe('from 1.0, no fixed version listed');
    expect(rangeText(['>=0'])).toBe('every version, no fixed version listed');
    expect(rangeText(['>=0.0.0-0', '<0.2.0'])).toBe('before 0.2.0');
    expect(rangeText(['>=1.0.0', '<1.1.0', '>=2.0.0', '<2.0.5'])).toBe('from 1.0.0, before 1.1.0; from 2.0.0, before 2.0.5');
    expect(rangeText(['?git=unknown'])).toBe('only a git commit range is given');
    expect(rangeText(['?constructor=1'])).toBe('a "constructor" bound that cannot be compared');
    expect(rangesText([['>=0', '<1.0'], ['>=2.0', '<2.1']])).toBe('before 1.0; from 2.0, before 2.1');
  });
});

describe('mergePackageFiles', () => {
  const row = (id: string, s: number) => ROW_COLS.map((c) => (c === 'id' ? id : c === 's' ? s : c === 'c' || c === 'r' ? [] : c === 'tier' ? 'quiet' : c === 'pub' ? '2024-01-01T00:00:00Z' : c === 'x' || c === 'w' || c === 'k' || c === 'ai' ? 0 : c === 'cv' || c === 'e' || c === 'kd' || c === 'b' ? null : ''));
  const file = (rows: unknown[][], packages: PackagesFile['packages'], matched: number): PackagesFile => ({
    schema_version: SCHEMA_VERSION,
    generated_at: '2026-11-26T00:00:00Z',
    scope: '',
    attribution: [],
    sources: PACKAGE_ECOSYSTEMS.map((ecosystem) => ({ ecosystem, ok: ecosystem !== 'NuGet', stale: false, fetched_at: null, modified: null, advisories: 10, matched: ecosystem === 'npm' ? matched : 0, error: null })),
    distinct: { advisories: 40, matched },
    cves: { cols: ROW_COLS, rows },
    packages,
  });
  const tracked = file([row('CVE-2026-1', 90)], { npm: { lodash: [['CVE-2026-1', 'GHSA-a', [['>=0', '<1']]]] }, PyPI: {} }, 1);
  const older = file(
    [row('CVE-2020-1', 10), row('CVE-2026-1', 5)],
    { npm: { lodash: [['CVE-2020-1', 'GHSA-b', [['>=0', '<2']]]], ['__proto__']: [['CVE-2020-1', 'GHSA-c', [['>=0']]]], dup: [['CVE-2026-1', 'GHSA-d', [['>=0']]]] } },
    2,
  );

  it('joins rows and entries, keeping the tracked row of a CVE in both', () => {
    const m = mergePackageFiles(tracked, older);
    expect(rowsFromTable(m.cves).map((r) => [r.id, r.s])).toEqual([['CVE-2026-1', 90], ['CVE-2020-1', 10]]);
    expect(m.packages.npm!.lodash.map((e) => e[1])).toEqual(['GHSA-a', 'GHSA-b']);
    expect(Object.prototype.hasOwnProperty.call(m.packages.npm, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(m.packages.npm)).toBe(Object.prototype);
    expect(m.packages.npm!.dup).toBeUndefined();
    expect(m.packages.PyPI).toEqual({});
    expect(m.sources.find((s) => s.ecosystem === 'npm')?.matched).toBe(3);
    expect(m.distinct).toEqual({ advisories: 40, matched: 3 });
  });

  it('is the tracked file itself without an older one', () => {
    expect(mergePackageFiles(tracked, null)).toBe(tracked);
  });
});
