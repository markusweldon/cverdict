import { describe, expect, it } from 'vitest';
import { testIndex } from './fixtures/index';
import { checkComponents, groupByTier, type CheckResult } from './match';
import { parse, type Component } from './parse';

const check = (text: string, filename = '', down?: string[]): CheckResult => checkComponents(parse(text, filename), testIndex({ down }));
const purls = (...list: string[]) => check(list.join('\n'));
const ids = (r: CheckResult, affected = true) =>
  r.cves
    .filter((c) => c.affected === affected)
    .map((c) => c.row.id)
    .sort();

describe('checkComponents', () => {
  it('finds Log4Shell in an affected log4j-core, and not in a fixed one', () => {
    const r = purls('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.12.2');
    expect(ids(r)).toEqual(['CVE-2021-44228', 'CVE-2021-45046']);
    const shell = r.cves.find((c) => c.row.id === 'CVE-2021-44228')!;
    expect(shell.packages).toEqual([
      {
        eco: 'Maven',
        name: 'org.apache.logging.log4j:log4j-core',
        version: '2.14.1',
        unchecked: null,
        advisories: [{ id: 'GHSA-jfh8-c2jp-5v3q', ranges: [['>=2.13.0', '<2.15.0'], ['>=2.0-beta9', '<2.3.1'], ['>=2.4', '<2.12.2']], versions: [], listed: false, fixedIn: '2.15.0' }],
      },
    ]);
    expect(r.clean.map((c) => c.version).sort()).toEqual(['2.12.2', '2.17.1']);
    expect(r.affectedPackages).toBe(1);
    expect(r.indexCves).toBe(20);
  });

  it('shows a CVE with two advisories once, with both', () => {
    const r = purls('pkg:pypi/Brotli@1.1.0');
    expect(r.cves).toHaveLength(1);
    expect(r.cves[0].packages[0].advisories.map((a) => a.id)).toEqual(['GHSA-9v8h-qqgm-4m35', 'PYSEC-2026-4322']);
  });

  it('normalises PyPI names and treats a release candidate as before the release', () => {
    expect(ids(purls('pkg:pypi/apache_airflow@1.10.10'))).toEqual(['CVE-2020-11978']);
    expect(ids(purls('pkg:pypi/Apache.Airflow@1.10.11'))).toEqual([]);
  });

  it('matches listed extra versions exactly', () => {
    const r = purls('pkg:composer/moodle/moodle@v4.0.0-beta', 'pkg:composer/moodle/moodle@4.0.0');
    expect(r.cves[0].packages.map((p) => [p.version, p.advisories[0].listed, p.advisories[0].fixedIn])).toEqual([['v4.0.0-beta', true, null]]);
  });

  it('reads Go versions with a v prefix, the standard library from an SBOM, and a fixed bound that is missing', () => {
    const r = purls('pkg:golang/code.gitea.io/gitea@v1.20.0', 'pkg:golang/stdlib@go1.22.3', 'pkg:golang/stdlib@go1.22.5');
    expect(ids(r)).toEqual(['CVE-2026-111943', 'CVE-2026-60004']);
    const gitea = r.cves.find((c) => c.row.id === 'CVE-2026-60004')!;
    expect(gitea.packages[0].advisories[0].fixedIn).toBeNull();
    expect(r.cves.find((c) => c.row.id === 'CVE-2026-111943')!.packages[0].advisories[0].fixedIn).toBe('1.22.4');
  });

  it('says "possibly affected" for what it cannot compare, never "not affected"', () => {
    const r = check(['pkg:npm/mixed@1.5.0', 'pkg:npm/mixed@3.0.0', 'pkg:npm/mixed@not.a.version', 'pkg:cargo/git-only@1.0.0', 'pkg:gem/capped@1.0.0'].join('\n'));
    const byVersion = new Map(r.cves.flatMap((c) => c.packages.map((p) => [`${p.name}@${p.version}`, [c.affected, p.unchecked]])));
    // One range says affected and one cannot be read: affected.
    expect(byVersion.get('mixed@1.5.0')).toEqual([true, null]);
    expect(byVersion.get('mixed@3.0.0')).toEqual([true, 'range']);
    expect(byVersion.get('mixed@not.a.version')).toEqual([true, 'version']);
    expect(byVersion.get('git-only@1.0.0')).toEqual([false, 'range']);
    expect(byVersion.get('capped@1.0.0')).toEqual([false, 'range']);
    expect(r.clean).toEqual([]);
    expect(r.affectedPackages).toBe(1);
    expect(r.possiblePackages).toBe(4);
  });

  it('marks packages without an exact version as possibly affected only when a tracked CVE names them', () => {
    const r = check('pillow>=11\nflask>=3\n', 'requirements.txt');
    expect(ids(r, false)).toEqual(['CVE-2026-112393', 'CVE-2026-112403', 'CVE-2026-112900']);
    expect(r.cves.every((c) => c.packages[0].unchecked === 'not-exact')).toBe(true);
    expect(r.clean.map((c) => c.name)).toEqual(['flask']);
  });

  it('reports a go.mod replace to a local directory as possibly affected', () => {
    const r = check('module x\nrequire example.com/replaced v0.50.0\nreplace example.com/replaced => ../replaced\n');
    expect(r.cves.map((c) => [c.row.id, c.affected, c.packages[0].unchecked])).toEqual([['CVE-2026-53999', false, 'go-local']]);
    expect(r.notChecked.map((g) => g.reason)).toEqual(['go-stdlib']);
  });

  it('reports a lowercased golang package URL of a mixed-case module as possibly affected, never clean', () => {
    // The purl spec lowercases golang names; Go module paths are case-sensitive.
    const hit = (purl: string) => purls(purl).cves.map((c) => [c.row.id, c.affected, c.packages[0].unchecked, c.packages[0].named]);
    expect(hit('pkg:golang/github.com/OpenListTeam/OpenList/v4@v4.0.0')).toEqual([['CVE-2026-102663', true, null, undefined]]);
    expect(hit('pkg:golang/github.com/openlistteam/openlist/v4@v4.0.0')).toEqual([['CVE-2026-102663', false, 'name-case', 'github.com/OpenListTeam/OpenList/v4']]);
    // Outside the range in either spelling: not affected.
    expect(purls('pkg:golang/github.com/openlistteam/openlist/v4@v4.2.4').clean).toHaveLength(1);
    expect(purls('pkg:golang/github.com/openlistteam/openlist@v4.0.0').cves).toEqual([]);
  });

  it('reports a module whose package an advisory names as possibly affected', () => {
    const r = check('module x\nrequire (\n\tgithub.com/klauspost/compress v1.16.0\n\texample.com/nested v1.0.0\n\texample.com/nested/sub v1.0.0\n\texample.com/major v1.0.0\n)\n', 'go.mod');
    const byPkg = r.cves.flatMap((c) => c.packages.map((p) => [c.row.id, p.name, c.affected, p.unchecked, p.named ?? null]));
    expect(byPkg).toEqual([
      // .../zstd is a package of the module; the advisory's range is compared with the module's version.
      ['CVE-2026-116591', 'github.com/klauspost/compress', false, 'go-package', 'github.com/klauspost/compress/zstd'],
      // A path that is itself a module in the file belongs to that module only (Go's longest-prefix rule).
      ['CVE-2026-50007', 'example.com/nested/sub', true, null, null],
    ]);
    // The module's own advisory keeps its answer (fixed in 1.10.0), and a /v2 path is another module.
    expect(r.clean.map((c) => c.name).sort()).toEqual(['example.com/major', 'example.com/nested']);
    expect(r.possiblePackages).toBe(1);
    // A fixed module version: the package's range is compared too.
    expect(check('module x\nrequire github.com/klauspost/compress v1.20.2\n', 'go.mod').cves).toEqual([]);
  });

  it('reports a lowercased golang package URL as possibly affected when the advisory names a path inside it in other letter case', () => {
    // A real key shape: github.com/luskaner/ageLANServer/server, a path inside a mixed-case module.
    const file = testIndex();
    file.packages.Go!['github.com/luskaner/ageLANServer/server'] = [['CVE-2026-50007', 'GHSA-qqqq-rrrr-ssss', [['>=0', '<9.0.0']]]];
    const hit = (...list: string[]) =>
      checkComponents(parse(list.join('\n')), file).cves.flatMap((c) => c.packages.map((p) => [c.row.id, p.name, c.affected, p.unchecked, p.named]));
    const named = 'github.com/luskaner/ageLANServer/server';
    expect(hit('pkg:golang/github.com/luskaner/ageLANServer@v1.2.0')).toEqual([['CVE-2026-50007', 'github.com/luskaner/ageLANServer', false, 'go-package', named]]);
    expect(hit('pkg:golang/github.com/luskaner/agelanserver@v1.2.0')).toEqual([['CVE-2026-50007', 'github.com/luskaner/agelanserver', false, 'go-package', named]]);
    // Both spellings in one file: each is reported.
    expect(hit('pkg:golang/github.com/luskaner/ageLANServer@v1.2.0', 'pkg:golang/github.com/luskaner/agelanserver@v1.2.0').map((h) => h[1])).toEqual([
      'github.com/luskaner/ageLANServer',
      'github.com/luskaner/agelanserver',
    ]);
    // The path itself, lowercased, is a module of the file: it owns its advisories, the parent does not.
    expect(hit('pkg:golang/github.com/luskaner/agelanserver@v1.2.0', 'pkg:golang/github.com/luskaner/agelanserver/server@v1.2.0')).toEqual([
      ['CVE-2026-50007', 'github.com/luskaner/agelanserver/server', false, 'name-case', named],
    ]);
  });

  it('lists packages of an ecosystem without data as not checked, never as clean', () => {
    const r = check('pkg:nuget/CefSharp.Common@85.0.0\npkg:deb/debian/libc6@2.36\npkg:rpm/bash@5\n');
    expect(r.cves).toEqual([]);
    expect(r.clean).toEqual([]);
    expect(r.notChecked.map((g) => [g.reason, g.eco, g.items.map((c: Component) => c.name)])).toEqual([
      ['eco-down', 'NuGet', ['CefSharp.Common']],
      ['ecosystem', undefined, ['debian/libc6', 'bash']],
    ]);
    expect(r.checked).toBe(0);
    // With NuGet data, the same file is checked.
    expect(ids(checkComponents(parse('pkg:nuget/CefSharp.Common@85.0.0'), testIndex({ down: [] })))).toEqual(['CVE-2022-0609']);
  });

  it('counts distinct packages once and keeps names like __proto__ as plain names', () => {
    const r = purls('pkg:npm/__proto__@1.0.0', 'pkg:npm/__proto__@1.0.0', 'pkg:npm/constructor@1.0.0', 'pkg:npm/toString@1.0.0', 'pkg:npm/hasOwnProperty@1.0.0');
    expect(r.total).toBe(5);
    expect(r.distinct).toBe(4);
    expect(ids(r)).toEqual(['CVE-2026-50004']);
    expect(r.clean.map((c) => c.name).sort()).toEqual(['constructor', 'hasOwnProperty', 'toString']);
  });

  it('keeps an advisory ID that fails the pattern as data (the page shows it without a link)', () => {
    expect(purls('pkg:npm/bad-id@1.0.0').cves[0].packages[0].advisories[0].id).toBe('not an advisory id');
  });

  it('ignores malformed entries in a tampered index', () => {
    const file = testIndex();
    (file.packages.npm as Record<string, unknown>).junk = [null, 'x', ['CVE-2026-1', 5, []], ['CVE-2026-50003', 'GHSA-x', 'not ranges']];
    expect(checkComponents(parse('pkg:npm/junk@1.0.0'), file).clean.map((c) => c.name)).toEqual(['junk']);
  });
});

describe('groupByTier', () => {
  const r = purls('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'pkg:pypi/pillow@12.0.0', 'pkg:npm/mixed@1.5.0', 'pkg:cargo/git-only@1.0.0');
  const at = (knob: number) => Object.fromEntries([...groupByTier(r.cves, knob)].map(([g, list]) => [g, list.map((c) => c.row.id)]));

  it('groups affected CVEs by tier at the knob, possibly affected ones apart', () => {
    expect(at(50)).toEqual({
      // Same score: the newest first.
      exploited: ['CVE-2021-45046', 'CVE-2021-44228'],
      likely: ['CVE-2026-50003', 'CVE-2026-112900'],
      watch: ['CVE-2026-112403', 'CVE-2026-112393'],
      quiet: [],
      possible: ['CVE-2026-50002'],
    });
  });

  it('moves CVEs between tiers as the knob turns', () => {
    expect(at(30).likely).toEqual(['CVE-2026-50003', 'CVE-2026-112900', 'CVE-2026-112403', 'CVE-2026-112393']);
    expect(at(80)).toMatchObject({ likely: ['CVE-2026-50003'], watch: ['CVE-2026-112900', 'CVE-2026-112403', 'CVE-2026-112393'] });
  });
});
