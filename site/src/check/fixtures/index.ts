/** A small hand-made v1/packages.json for the matching and session tests. */
import { PACKAGE_ECOSYSTEMS, ROW_COLS, SCHEMA_VERSION, type PackagesFile } from '../../../../shared/contract';
import { ATTRIBUTION } from '../../../../shared/packages';

/** One index.json row: id, pub, cna, v, p, t, s, tier, x, w, k, ai, c, r, cv, e, kd, b. */
function row(id: string, s: number, x: 0 | 1, w: 0 | 1, pub: string, v: string, p: string): unknown[] {
  return [id, pub, 'GitHub_M', v, p, `${p} test CVE`, s, x ? 'exploited' : w || s >= 50 ? 'likely' : s >= 25 ? 'watch' : 'quiet', x, w, x, 0, [], [], null, null, null, null];
}

export function testIndex(overrides: { down?: string[] } = {}): PackagesFile {
  const down = new Set(overrides.down ?? ['NuGet']);
  // Built from JSON text so that "__proto__" is an own key, as JSON.parse gives it to the site.
  const packages = JSON.parse(
    JSON.stringify({
      Maven: {
        'org.apache.logging.log4j:log4j-core': [
          ['CVE-2021-44228', 'GHSA-jfh8-c2jp-5v3q', [['>=2.13.0', '<2.15.0'], ['>=2.0-beta9', '<2.3.1'], ['>=2.4', '<2.12.2']]],
          ['CVE-2021-45046', 'GHSA-7rjr-3q55-vv33', [['>=2.13.0', '<2.16.0'], ['>=2.4.0', '<2.12.2'], ['>=0', '<2.3.1']]],
        ],
      },
      PyPI: {
        brotli: [
          ['CVE-2026-111497', 'GHSA-9v8h-qqgm-4m35', [['>=1.0.3', '<1.2.1']]],
          ['CVE-2026-111497', 'PYSEC-2026-4322', [['>=0', '<1.2.1']]],
        ],
        'apache-airflow': [['CVE-2020-11978', 'GHSA-rvmq-4x66-q7j3', [['>=0', '<1.10.11rc1']]]],
        pillow: [
          ['CVE-2026-112900', 'GHSA-w889-685w-c8fh', [['>=0', '<13.0.0']]],
          ['CVE-2026-112403', 'GHSA-8g5g-8vmr-9782', [['>=11.0.0', '<13.0.0']]],
          ['CVE-2026-112393', 'GHSA-332p-7hrc-92wf', [['>=0', '<13.0.0']]],
        ],
      },
      Go: {
        stdlib: [['CVE-2026-111943', 'GO-2026-6809', [['>=0', '<1.21.11'], ['>=1.22.0-0', '<1.22.4']]]],
        'code.gitea.io/gitea': [['CVE-2026-60004', 'GO-2026-6433', [['>=1.17.0']]]],
        'example.com/replaced': [['CVE-2026-53999', 'GO-2026-5373', [['>=0', '<0.58.0']]]],
        // Real keys: a module path with capitals, and an advisory that names a package path.
        'github.com/OpenListTeam/OpenList/v4': [['CVE-2026-102663', 'GHSA-p6ph-3jx2-3337', [['>=0', '<4.2.4']]]],
        'github.com/klauspost/compress/zstd': [['CVE-2026-116591', 'GHSA-fpmh-frq8-7rj8', [['>=0', '<1.20.2']]]],
        'github.com/klauspost/compress': [['CVE-2026-50007', 'GHSA-qqqq-rrrr-ssss', [['>=0', '<1.10.0']]]],
        'example.com/nested/sub': [['CVE-2026-50007', 'GHSA-qqqq-rrrr-ssss', [['>=0', '<9.0.0']]]],
        'example.com/major/v2/pkg': [['CVE-2026-50007', 'GHSA-qqqq-rrrr-ssss', [['>=0', '<9.0.0']]]],
      },
      Packagist: {
        'moodle/moodle': [['CVE-2026-50001', 'GHSA-aaaa-bbbb-cccc', [['>=4.1.0', '<4.1.5']], ['v4.0.0-beta']]],
      },
      'crates.io': {
        'git-only': [['CVE-2026-50002', 'RUSTSEC-2026-0001', [['?git=unknown']]]],
      },
      npm: {
        mixed: [['CVE-2026-50003', 'GHSA-dddd-eeee-ffff', [['>=1.0.0', '<2.0.0'], ['?limit=3.0.0']]]],
        // A computed key is an own property; a literal __proto__ key would set the prototype.
        ['__proto__']: [['CVE-2026-50004', 'GHSA-gggg-hhhh-jjjj', [['>=0', '<2.0.0']]]],
        'bad-id': [['CVE-2026-50005', 'not an advisory id', [['>=0', '<9.0.0']]]],
      },
      RubyGems: {
        capped: [['CVE-2026-50006', 'GHSA-kkkk-mmmm-pppp', [['?versions=capped']]]],
      },
      NuGet: {
        'cefsharp.common': [['CVE-2022-0609', 'GHSA-vv6j-ww6x-54gx', [['>=0', '<98.1.210']]]],
      },
    }),
  ) as PackagesFile['packages'];
  for (const eco of down) delete (packages as Record<string, unknown>)[eco];
  const rows = [
    row('CVE-2021-44228', 100, 1, 0, '2021-12-10T00:00:00Z', 'Apache Software Foundation', 'Apache Log4j2'),
    row('CVE-2021-45046', 100, 1, 0, '2021-12-14T00:00:00Z', 'Apache Software Foundation', 'Apache Log4j'),
    row('CVE-2026-111497', 100, 1, 0, '2026-10-30T00:00:00Z', 'Google', 'Brotli'),
    row('CVE-2020-11978', 100, 1, 0, '2020-07-17T00:00:00Z', 'Apache', 'Airflow'),
    row('CVE-2026-112900', 56, 0, 0, '2026-10-31T00:00:00Z', 'python-pillow', 'Pillow'),
    row('CVE-2026-112403', 48, 0, 0, '2026-10-30T00:00:00Z', 'python-pillow', 'Pillow'),
    row('CVE-2026-112393', 38, 0, 0, '2026-10-29T00:00:00Z', 'python-pillow', 'Pillow'),
    row('CVE-2026-111943', 22, 0, 0, '2026-10-28T00:00:00Z', 'Go', 'stdlib'),
    row('CVE-2026-60004', 100, 1, 0, '2026-10-20T00:00:00Z', 'Gitea', 'Gitea'),
    row('CVE-2026-53999', 12, 0, 0, '2026-10-10T00:00:00Z', 'example', 'replaced'),
    row('CVE-2026-50001', 30, 0, 0, '2026-10-11T00:00:00Z', 'Moodle', 'Moodle'),
    row('CVE-2026-50002', 20, 0, 0, '2026-10-12T00:00:00Z', 'example', 'git-only'),
    row('CVE-2026-50003', 60, 0, 1, '2026-10-13T00:00:00Z', 'example', 'mixed'),
    row('CVE-2026-50004', 10, 0, 0, '2026-10-14T00:00:00Z', 'example', 'proto'),
    row('CVE-2026-50005', 10, 0, 0, '2026-10-15T00:00:00Z', 'example', 'bad-id'),
    row('CVE-2026-50006', 10, 0, 0, '2026-10-16T00:00:00Z', 'example', 'capped'),
    row('CVE-2022-0609', 100, 1, 0, '2022-04-12T00:00:00Z', 'Google', 'Chrome'),
    row('CVE-2026-102663', 0, 0, 0, '2026-10-12T18:49:23Z', 'OpenListTeam', 'OpenList'),
    row('CVE-2026-116591', 10, 0, 0, '2026-10-26T21:54:33Z', 'klauspost', 'compress'),
    row('CVE-2026-50007', 10, 0, 0, '2026-10-17T00:00:00Z', 'example', 'go-paths'),
  ];
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: '2026-11-03T08:48:00.000Z',
    scope: 'test index',
    attribution: [...ATTRIBUTION],
    sources: PACKAGE_ECOSYSTEMS.map((ecosystem) => ({
      ecosystem,
      ok: !down.has(ecosystem),
      stale: ecosystem === 'PyPI',
      fetched_at: down.has(ecosystem) ? null : '2026-11-03T08:47:00.000Z',
      modified: down.has(ecosystem) ? null : '2026-11-03T08:00:00.000Z',
      advisories: 100,
      matched: down.has(ecosystem) ? 0 : 10,
      error: down.has(ecosystem) ? 'download failed' : null,
    })),
    cves: { cols: ROW_COLS, rows },
    packages,
  };
}
