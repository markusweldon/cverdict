/**
 * Checks files against packages.json with the Check page's own parser and matcher, and turns
 * the results into findings: one per (CVE, package, file), with the line the package is on.
 */
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { KNOB_DEFAULT, type PackagesFile, type Row, type Tier } from '../../shared/contract';
import { checkComponents, groupByTier, type CheckResult, type Group, type PackageHit } from '../../site/src/check/match';
import { FORMAT_LABEL, ParseError, parse, type FormatId } from '../../site/src/check/parse';
import { COMPARATORS } from '../../shared/versions';

/** The Check page reads files up to this size. */
export const MAX_FILE_BYTES = 50 * 1024 * 1024;

export type FailOn = Tier | 'never';
export const FAIL_ON: readonly FailOn[] = ['exploited', 'likely', 'watch', 'quiet', 'never'];
const RANK: Readonly<Record<Group, number>> = { exploited: 4, likely: 3, watch: 2, quiet: 1, possible: 0 };

export interface FileReport {
  /** Relative path, with forward slashes. */
  path: string;
  format: FormatId | null;
  /** Why the file could not be read; then there is no result. */
  error: string | null;
  result: CheckResult | null;
}

export interface Finding {
  group: Group;
  row: Row;
  /** One package (with its version) in one file. */
  pkg: PackageHit;
  file: string;
  /** 1-based line of the package in the file, when it can be found. */
  line: number | null;
  /** The lowest version that fixes every matching advisory (lowestFix), if one is known. */
  fixedIn: string | null;
  /** A tracked CVE (it has a CVE page); false for one from packages-older.json. */
  tracked: boolean;
}

export interface Report {
  generatedAt: string;
  knob: number;
  files: FileReport[];
  findings: Finding[];
  /** Distinct packages read and compared, over all files. */
  packages: number;
  checked: number;
  indexCves: number;
  /** Ecosystems whose advisory data was missing in the last run. */
  ecosystemsDown: string[];
  /** What the index covered: tracked CVEs, older ones (packages-older.json), distinct advisories naming a CVE, and why older ones are missing. */
  coverage: { tracked: number; older: number; advisories: number; olderError: string | null };
  /** Notes from the parser, per file. */
  notes: { file: string; text: string }[];
}

/**
 * 1-based line numbers by package, found once per file. The best line names the package as a whole
 * name (so "lodash" is not found in "lodash.merge") together with its version; then one naming it
 * alone; then any line holding the text. Lines with a URL are passed over for the first two, as a
 * download URL repeats the name and version (npm's "resolved").
 */
export function lineFinder(text: string): (name: string, version: string | null) => number | null {
  const lines = text.split('\n');
  const cache = new Map<string, number | null>();
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return (name, version) => {
    const key = `${name}\u0000${version ?? ''}`;
    if (cache.has(key)) return cache.get(key)!;
    const whole = new RegExp(`(?<![\\w.-])${esc(name)}(?![\\w-]|\\.[\\w])`);
    let both: number | null = null;
    let named: number | null = null;
    let any: number | null = null;
    for (let i = 0; i < lines.length && both === null; i++) {
      const l = lines[i];
      if (!l.includes(name)) continue;
      any ??= i + 1;
      if (l.includes('://') || !whole.test(l)) continue;
      named ??= i + 1;
      if (version && l.includes(version)) both = i + 1;
    }
    const at = both ?? named ?? any;
    cache.set(key, at);
    return at;
  };
}

/**
 * The lowest version that fixes every matching advisory: the highest of their next fixed versions, by
 * the ecosystem's own version order. Null when an advisory names no fix (the package needs another
 * way out), or a fix cannot be compared.
 */
export function lowestFix(pkg: Pick<PackageHit, 'eco' | 'advisories'>): string | null {
  const c = COMPARATORS[pkg.eco];
  let best: { key: unknown; text: string } | null = null;
  for (const a of pkg.advisories) {
    if (a.fixedIn === null) return null;
    const key = c.parse(a.fixedIn);
    if (key === null) return null;
    if (best === null || c.cmp(key, best.key) > 0) best = { key, text: a.fixedIn };
  }
  return best?.text ?? null;
}

/** Group order for findings: Exploited first, possibly affected last; within a group by score, then CVE. */
export const compareFindings = (a: Finding, b: Finding) =>
  RANK[b.group] - RANK[a.group] || b.row.s - a.row.s || a.row.id.localeCompare(b.row.id) || a.file.localeCompare(b.file) || a.pkg.name.localeCompare(b.pkg.name);

/** Which CVEs of the index came from packages-older.json, and why it is missing (Loaded in data.ts). */
export interface OlderInfo {
  olderIds: ReadonlySet<string>;
  olderError: string | null;
}

/** Check `files` (relative to `cwd`) at evidence bar `knob`. Reads files; no network. */
export function checkFiles(files: readonly string[], cwd: string, index: PackagesFile, knob = KNOB_DEFAULT, older: OlderInfo = { olderIds: new Set(), olderError: null }): Report {
  const reports: FileReport[] = [];
  const findings: Finding[] = [];
  const notes: Report['notes'] = [];
  let packages = 0;
  let checked = 0;
  for (const path of files) {
    const abs = resolve(cwd, path);
    let text: string;
    try {
      if (statSync(abs).size > MAX_FILE_BYTES) {
        reports.push({ path, format: null, error: `larger than ${MAX_FILE_BYTES / 1024 / 1024} MB`, result: null });
        continue;
      }
      text = readFileSync(abs, 'utf8');
    } catch (e) {
      reports.push({ path, format: null, error: `could not be read: ${(e as Error).message}`, result: null });
      continue;
    }
    let result: CheckResult;
    try {
      result = checkComponents(parse(text, path), index);
    } catch (e) {
      reports.push({ path, format: null, error: e instanceof ParseError ? e.message : `could not be read: ${(e as Error).message}`, result: null });
      continue;
    }
    reports.push({ path, format: result.format, error: null, result });
    packages += result.distinct;
    checked += result.checked;
    for (const n of result.notes) notes.push({ file: path, text: n });
    const line = lineFinder(text);
    for (const [group, hits] of groupByTier(result.cves, knob)) {
      for (const hit of hits) {
        for (const pkg of hit.packages) {
          // A CVE confirmed for one package of the file lists its unconfirmed packages under "possible".
          const g: Group = group !== 'possible' && pkg.unchecked !== null ? 'possible' : group;
          findings.push({ group: g, row: hit.row, pkg, file: path, line: line(pkg.name, pkg.version), fixedIn: lowestFix(pkg), tracked: !older.olderIds.has(hit.row.id) });
        }
      }
    }
  }
  findings.sort(compareFindings);
  return {
    generatedAt: index.generated_at,
    knob,
    files: reports,
    findings,
    packages,
    checked,
    indexCves: index.cves.rows.length,
    ecosystemsDown: index.sources.filter((s) => !s.ok).map((s) => s.ecosystem),
    coverage: { tracked: index.cves.rows.length - older.olderIds.size, older: older.olderIds.size, advisories: index.distinct?.advisories ?? 0, olderError: older.olderError },
    notes,
  };
}

/** Findings that fail the run: confirmed ones at or above `failOn`. */
export function failing(report: Pick<Report, 'findings'>, failOn: FailOn): Finding[] {
  if (failOn === 'never') return [];
  return report.findings.filter((f) => f.group !== 'possible' && RANK[f.group] >= RANK[failOn]);
}

/** Distinct CVEs per group. */
export function countByGroup(findings: readonly Finding[]): Record<Group, number> {
  const out: Record<Group, Set<string>> = { exploited: new Set(), likely: new Set(), watch: new Set(), quiet: new Set(), possible: new Set() };
  for (const f of findings) out[f.group].add(f.row.id);
  return { exploited: out.exploited.size, likely: out.likely.size, watch: out.watch.size, quiet: out.quiet.size, possible: out.possible.size };
}

export const formatLabel = (f: FormatId | null) => (f ? (FORMAT_LABEL.get(f) ?? f) : 'unknown');
