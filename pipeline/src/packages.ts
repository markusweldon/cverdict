/**
 * v1/packages.json and v1/packages-older.json (docs/DATA.md): which package versions CVEs affect,
 * for Check Deps, the CLI and the MCP server. Built every run from the OSV mirror (sources/osv.ts).
 *
 * - packages.json: the tracked CVEs, those with a detail shard (window, KEV, exploited catalogs,
 *   woke up), with their full rows.
 * - packages-older.json: every other CVE an advisory names, all published before the window and
 *   scored by the same model, with slim rows (no chip lists, short titles) and no CVE page.
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

/** Title length kept in packages-older.json rows. */
export const OLDER_TITLE_MAX = 80;

export function olderPackagesScope(windowDays: number): string {
  return (
    `Every other CVE that OSV.dev advisories name for a package in npm, PyPI, Maven, Go, crates.io, RubyGems, Packagist or NuGet: published more than ${windowDays} days ago, ` +
    'not in CISA KEV, not listed as exploited and not woken up, scored by the same model. They have no detail shard; rows keep no chip lists and titles of at most 80 characters. ' +
    'Only advisory IDs, package names and version ranges are kept.'
  );
}

/** Every CVE an ecosystem copy names, for the ingest to keep their records. Ecosystems without a usable copy name none. */
export function osvCveIds(osv: OsvData): Set<string> {
  const out = new Set<string>();
  for (const eco of PACKAGE_ECOSYSTEMS) {
    const copy = osv.mirror.ecosystems[eco];
    if (!osv.statuses[eco].ok || !copy) continue;
    for (const [, , cves] of copy.records) for (const c of cves) out.add(c);
  }
  return out;
}

/** A row as packages-older.json keeps it: no chip or reason lists, the title cut to OLDER_TITLE_MAX. */
export function slimRow(r: Row): Row {
  const t = r.t.length > OLDER_TITLE_MAX ? `${r.t.slice(0, OLDER_TITLE_MAX - 1).trimEnd()}…` : r.t;
  return { ...r, t, c: [], r: [] };
}

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
export function buildPackagesFile(osv: OsvData, rowById: ReadonlyMap<string, Row>, generatedAt: string, windowDays: number, scope = packagesScope(windowDays)): PackagesFile {
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
    scope,
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
