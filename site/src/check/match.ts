/**
 * Matches parsed packages against v1/packages.json: which tracked CVEs affect which versions.
 *
 * The rule is OSV's, through shared/versions.ts (the pipeline uses the same code): a version is
 * affected when an advisory lists it or one of its ranges contains it. Anything that cannot be
 * compared is "possibly affected", never clean. Lookups go through Maps built once from the file,
 * so a package named `__proto__` or `constructor` cannot reach Object.prototype.
 */
import { PACKAGE_ECOSYSTEMS, rowsFromTable, tierFor, type PackageAffect, type PackageEcosystem, type PackagesFile, type Row, type Tier } from '../../../shared/contract';
import { packageKey } from '../../../shared/packages';
import { COMPARATORS, compileRanges, matchAffect, parseEvent } from '../../../shared/versions';
import type { Component, FormatId, NoVersionReason, Parsed, SkipReason } from './parse';

export interface AdvisoryHit {
  id: string;
  ranges: string[][];
  /** Listed versions the ranges do not cover. */
  versions: string[];
  /** The advisory lists this exact version. */
  listed: boolean;
  /** The next fixed version above the user's, from the range that matched. */
  fixedIn: string | null;
}

/** Why a package is only possibly affected. */
export type UncheckedReason = NoVersionReason | 'version' | 'range';

export interface PackageHit {
  eco: PackageEcosystem;
  name: string;
  version: string | null;
  /** null: affected. */
  unchecked: UncheckedReason | null;
  advisories: AdvisoryHit[];
}

export interface CveHit {
  row: Row;
  /** At least one package is affected; otherwise every package is only possibly affected. */
  affected: boolean;
  packages: PackageHit[];
}

export type NotCheckedReason = SkipReason | 'eco-down';

export interface NotCheckedGroup {
  reason: NotCheckedReason;
  /** For 'eco-down': the ecosystem whose advisory data is missing. */
  eco?: PackageEcosystem;
  items: Component[];
}

export interface CheckResult {
  format: FormatId;
  /** Packages read from the file, and distinct ones (ecosystem, name, version). */
  total: number;
  distinct: number;
  /** Distinct packages that were compared (not in `notChecked`). */
  checked: number;
  /** CVEs in the index this result was checked against. */
  indexCves: number;
  cves: CveHit[];
  /** Distinct packages with at least one affecting CVE; and those only possibly affected. */
  affectedPackages: number;
  possiblePackages: number;
  notChecked: NotCheckedGroup[];
  /** Compared, and no tracked CVE affects them. */
  clean: Component[];
  notes: string[];
}

const NOT_CHECKED_ORDER: readonly NotCheckedReason[] = ['eco-down', 'ecosystem', 'no-purl', 'bad-purl', 'not-registry', 'dev-branch', 'go-stdlib'];

/** The fixed version the matching range names next above `version`, if any. */
function fixedIn(eco: PackageEcosystem, version: string, ranges: readonly (readonly string[])[]): string | null {
  const c = COMPARATORS[eco];
  const v = c.parse(version);
  if (v === null) return null;
  for (const range of ranges) {
    if (compileRanges(eco, [range])(version) !== true) continue;
    let best: { key: unknown; text: string } | null = null;
    for (const e of range) {
      const p = parseEvent(e);
      if (p?.op !== '<') continue;
      const key = c.parse(p.v);
      if (key !== null && c.cmp(key, v) > 0 && (best === null || c.cmp(key, best.key) < 0)) best = { key, text: p.v };
    }
    if (best) return best.text;
  }
  return null;
}

const isAffect = (a: unknown): a is PackageAffect => Array.isArray(a) && typeof a[0] === 'string' && typeof a[1] === 'string' && Array.isArray(a[2]);

/** Check every package of `parsed` against the index. Pure: no I/O. */
export function checkComponents(parsed: Parsed, file: PackagesFile): CheckResult {
  const rows = new Map(rowsFromTable(file.cves).map((r) => [r.id, r]));
  const index = new Map<PackageEcosystem, Map<string, PackageAffect[]>>();
  const ok = new Set(file.sources.filter((s) => s.ok).map((s) => s.ecosystem));
  for (const eco of PACKAGE_ECOSYSTEMS) {
    const pkgs: unknown = file.packages?.[eco];
    if (ok.has(eco) && typeof pkgs === 'object' && pkgs !== null) index.set(eco, new Map(Object.entries(pkgs as Record<string, PackageAffect[]>)));
  }

  // One entry per (ecosystem, package key, version, reason).
  const distinct = new Map<string, Component>();
  for (const c of parsed.components) {
    const k = [c.eco ?? `~${c.type ?? ''}`, c.eco ? packageKey(c.eco, c.name) : c.name, c.version ?? '', c.skip ?? c.noVersion ?? ''].join('\u0000');
    if (!distinct.has(k)) distinct.set(k, c);
  }

  const notChecked = new Map<string, NotCheckedGroup>();
  const skip = (reason: NotCheckedReason, c: Component, eco?: PackageEcosystem) => {
    const k = `${reason}:${eco ?? ''}`;
    let g = notChecked.get(k);
    if (!g) notChecked.set(k, (g = { reason, eco, items: [] }));
    g.items.push(c);
  };
  const byCve = new Map<string, PackageHit[]>();
  const clean: Component[] = [];
  const affectedKeys = new Set<string>();
  const possibleKeys = new Set<string>();

  for (const c of distinct.values()) {
    if (c.skip || !c.eco) {
      skip(c.skip ?? 'ecosystem', c);
      continue;
    }
    const eco = c.eco;
    const pkgs = index.get(eco);
    if (!pkgs) {
      skip('eco-down', c, eco);
      continue;
    }
    const key = packageKey(eco, c.name);
    const list = pkgs.get(key) ?? [];
    const perCve = new Map<string, { affected: AdvisoryHit[]; unchecked: AdvisoryHit[] }>();
    for (const a of list) {
      if (!isAffect(a)) continue;
      const [cve, id, ranges, versions = []] = a;
      const verdict = matchAffect(eco, c.version, ranges, versions);
      if (verdict === 'not_affected') continue;
      let e = perCve.get(cve);
      if (!e) perCve.set(cve, (e = { affected: [], unchecked: [] }));
      const listed = c.version !== null && versions.includes(c.version);
      const hit: AdvisoryHit = { id, ranges, versions, listed, fixedIn: verdict === 'affected' && c.version !== null && !listed ? fixedIn(eco, c.version, ranges) : null };
      (verdict === 'affected' ? e.affected : e.unchecked).push(hit);
    }
    const id = `${eco}\u0000${key}\u0000${c.version ?? ''}`;
    let any = false;
    for (const [cve, e] of perCve) {
      if (!rows.has(cve)) continue;
      any = true;
      const affected = e.affected.length > 0;
      const unchecked: UncheckedReason | null = affected ? null : (c.noVersion ?? (c.version !== null && COMPARATORS[eco].parse(c.version) === null ? 'version' : 'range'));
      let hits = byCve.get(cve);
      if (!hits) byCve.set(cve, (hits = []));
      hits.push({ eco, name: c.name, version: c.version, unchecked, advisories: affected ? e.affected : e.unchecked });
      (affected ? affectedKeys : possibleKeys).add(id);
    }
    if (!any) clean.push(c);
  }

  const cves: CveHit[] = [];
  for (const [cve, packages] of byCve) {
    const row = rows.get(cve);
    if (row) cves.push({ row, affected: packages.some((p) => p.unchecked === null), packages });
  }
  for (const k of affectedKeys) possibleKeys.delete(k);
  const groups = [...notChecked.values()].sort((a, b) => NOT_CHECKED_ORDER.indexOf(a.reason) - NOT_CHECKED_ORDER.indexOf(b.reason) || (a.eco ?? '').localeCompare(b.eco ?? ''));
  const skipped = groups.reduce((n, g) => n + g.items.length, 0);
  return {
    format: parsed.format,
    total: parsed.components.length,
    distinct: distinct.size,
    checked: distinct.size - skipped,
    indexCves: rows.size,
    cves,
    affectedPackages: affectedKeys.size,
    possiblePackages: possibleKeys.size,
    notChecked: groups,
    clean,
    notes: parsed.notes,
  };
}

export type Group = Tier | 'possible';
export const GROUP_ORDER: readonly Group[] = ['exploited', 'likely', 'watch', 'quiet', 'possible'];

/** CVEs grouped by tier at `knob` (possibly affected ones apart), each group by score, then newest. */
export function groupByTier(cves: readonly CveHit[], knob: number): Map<Group, CveHit[]> {
  const out = new Map<Group, CveHit[]>(GROUP_ORDER.map((g) => [g, []]));
  for (const c of cves) out.get(c.affected ? tierFor(c.row.s, c.row.x === 1, c.row.w === 1, knob) : 'possible')!.push(c);
  for (const list of out.values()) list.sort((a, b) => b.row.s - a.row.s || b.row.pub.localeCompare(a.row.pub) || a.row.id.localeCompare(b.row.id));
  return out;
}
