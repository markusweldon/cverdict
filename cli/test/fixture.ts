/** A small hand-built packages.json for the CLI tests (shapes from shared/contract.ts), and temp folders. */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { PACKAGE_ECOSYSTEMS, ROW_COLS, SCHEMA_VERSION, type PackagesFile, type Row } from '../../shared/contract';

export const GEN = '2026-11-26T17:47:24.413Z';

export function row(id: string, o: Partial<Row> = {}): Row {
  return { id, pub: '2026-11-20T10:00:00Z', cna: 'GitHub_M', v: 'acme', p: id.toLowerCase(), t: `Title of ${id}`, s: 40, tier: 'watch', x: 0, w: 0, k: 0, ai: 0, c: [], r: [], cv: 7.5, e: null, kd: null, b: null, ...o };
}

/**
 * Exploited: lodash < 4.17.21 (and >= 5.0.0 < 5.0.2 from a second advisory). Likely next (a Metasploit module, score 20):
 * requests < 2.31.0. Watch, score 45 (Likely next at a bar of 45): minimist < 1.2.6. Quiet: left-pad, every version.
 * The PyPI copy can be marked down with `down`.
 */
export function packagesFile(o: { down?: boolean } = {}): PackagesFile {
  const rows = [
    row('CVE-2026-1001', { s: 100, tier: 'exploited', x: 1, k: 1, kd: '2026-12-10', v: 'lodash', p: 'lodash' }),
    row('CVE-2026-1002', { s: 20, tier: 'likely', w: 1, v: 'psf', p: 'requests' }),
    row('CVE-2026-1003', { s: 45, tier: 'watch', v: 'minimist', p: 'minimist' }),
    row('CVE-2026-1004', { s: 10, tier: 'quiet', v: 'left-pad', p: 'left-pad' }),
  ];
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: GEN,
    scope: 'test',
    attribution: [],
    sources: PACKAGE_ECOSYSTEMS.map((ecosystem) => ({ ecosystem, ok: !(o.down && ecosystem === 'PyPI'), stale: false, fetched_at: GEN, modified: GEN, advisories: 1, matched: 1, error: null })) as PackagesFile['sources'],
    distinct: { advisories: 5, matched: 5 },
    cves: { cols: ROW_COLS, rows: rows.map((r) => ROW_COLS.map((c) => r[c])) },
    packages: {
      npm: {
        lodash: [
          ['CVE-2026-1001', 'GHSA-aaaa-bbbb-cccc', [['>=0', '<4.17.21']]],
          ['CVE-2026-1001', 'GHSA-dddd-eeee-ffff', [['>=5.0.0', '<5.0.2']]],
        ],
        minimist: [['CVE-2026-1003', 'GHSA-mmmm-mmmm-mmmm', [['>=0', '<1.2.6']]]],
        'left-pad': [['CVE-2026-1004', 'GHSA-llll-llll-llll', [['>=0']]]],
      },
      ...(o.down ? {} : { PyPI: { requests: [['CVE-2026-1002', 'PYSEC-2026-1', [['>=0', '<2.31.0']]]] } }),
    } as PackagesFile['packages'],
  };
}

/** package-lock.json (v3) with the given packages. */
export function npmLock(pkgs: Record<string, string>): string {
  const packages: Record<string, unknown> = { '': { name: 'app', version: '1.0.0' } };
  for (const [name, version] of Object.entries(pkgs)) packages[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz` };
  return `${JSON.stringify({ name: 'app', version: '1.0.0', lockfileVersion: 3, requires: true, packages }, null, 2)}\n`;
}

/** A fresh temp folder with these files (paths relative to it). */
export function tree(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'cverdict-check-'));
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), text);
  }
  return root;
}

/** A data folder holding v1/packages.json. */
export function dataDir(file: PackagesFile = packagesFile()): string {
  return tree({ 'v1/packages.json': JSON.stringify(file) });
}
