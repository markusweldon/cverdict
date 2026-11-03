/**
 * v1/packages.json (docs/DATA.md "packages.json"): which package versions the tracked CVEs affect,
 * for the in-browser SBOM check. Built every run from the OSV mirror (sources/osv.ts) and the rows
 * of every scored CVE, which are exactly the CVEs with a detail shard (window, KEV, woke up).
 */
import {
  PACKAGE_ECOSYSTEMS,
  ROW_COLS,
  SCHEMA_VERSION,
  type PackageAffect,
  type PackageSourceStatus,
  type PackagesFile,
  type Row,
} from '../../shared/contract';
import { ATTRIBUTION, packageKey } from '../../shared/packages';
import type { OsvData } from './sources/osv';

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function packagesScope(windowDays: number): string {
  return (
    `CVEs with a detail shard (published in the last ${windowDays} days, in CISA KEV, or in woke.json) that OSV.dev advisories ` +
    'name for a package in npm, PyPI, Maven, Go, crates.io, RubyGems, Packagist or NuGet. Only advisory IDs, package names and version ranges are kept.'
  );
}

/**
 * The file, byte-stable for the same inputs: package keys sorted, entries by CVE then advisory.
 * Ecosystems without a copy get no `packages` entry, so the site reports them as not checked.
 * Several affected objects of one advisory that end up under one package key are merged.
 */
export function buildPackagesFile(osv: OsvData, rowById: ReadonlyMap<string, Row>, generatedAt: string, windowDays: number): PackagesFile {
  const sources: PackageSourceStatus[] = [];
  const packages: PackagesFile['packages'] = {};
  const named = new Set<string>();
  const allIds = new Set<string>();
  const matchedIds = new Set<string>();
  for (const eco of PACKAGE_ECOSYSTEMS) {
    const status = osv.statuses[eco];
    const copy = osv.mirror.ecosystems[eco];
    let matched = 0;
    if (status.ok && copy) {
      // Package key → "cve advisory" → entry. Maps only: OSV names never index a plain object.
      const byKey = new Map<string, Map<string, PackageAffect>>();
      for (const [id, , cves, affected] of copy.records) {
        allIds.add(id);
        const hit = cves.filter((c) => rowById.has(c));
        if (hit.length === 0) continue;
        matched++;
        matchedIds.add(id);
        for (const [name, ranges, extra] of affected) {
          const key = packageKey(eco, name);
          let entries = byKey.get(key);
          if (!entries) byKey.set(key, (entries = new Map()));
          for (const cve of hit) {
            named.add(cve);
            const k = `${cve} ${id}`;
            const cur = entries.get(k);
            if (!cur) {
              entries.set(k, extra && extra.length > 0 ? [cve, id, ranges.map((r) => [...r]), [...extra]] : [cve, id, ranges.map((r) => [...r])]);
              continue;
            }
            for (const r of ranges) if (!cur[2].some((x) => x.join('\n') === r.join('\n'))) cur[2].push([...r]);
            if (extra && extra.length > 0) cur[3] = [...new Set([...(cur[3] ?? []), ...extra])];
          }
        }
      }
      packages[eco] = Object.fromEntries(
        [...byKey.keys()].sort(byText).map((key) => [key, [...byKey.get(key)!.values()].sort((a, b) => byText(a[0], b[0]) || byText(a[1], b[1]))]),
      );
    }
    sources.push({
      ecosystem: eco,
      ok: status.ok && copy !== undefined,
      stale: status.stale,
      fetched_at: status.fetched_at,
      modified: status.modified,
      advisories: status.advisories,
      matched,
      error: status.error,
    });
  }
  const ids = [...named].sort(byText);
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: generatedAt,
    scope: packagesScope(windowDays),
    attribution: ATTRIBUTION.map((a) => ({ ...a, prefixes: [...a.prefixes] })),
    sources,
    distinct: { advisories: allIds.size, matched: matchedIds.size },
    cves: { cols: ROW_COLS, rows: ids.map((id) => ROW_COLS.map((c) => rowById.get(id)![c])) },
    packages,
  };
}

/** Packages, CVEs and per-ecosystem CVE counts, for the run summary. */
export function packagesSummary(file: PackagesFile): { packages: number; cves: number; byEcosystem: { ecosystem: string; packages: number; cves: number }[] } {
  const byEcosystem = PACKAGE_ECOSYSTEMS.filter((eco) => file.packages[eco]).map((eco) => {
    const pkgs = file.packages[eco]!;
    const cves = new Set(Object.values(pkgs).flatMap((entries) => entries.map((e) => e[0])));
    return { ecosystem: eco, packages: Object.keys(pkgs).length, cves: cves.size };
  });
  return { packages: byEcosystem.reduce((a, e) => a + e.packages, 0), cves: file.cves.rows.length, byEcosystem };
}
