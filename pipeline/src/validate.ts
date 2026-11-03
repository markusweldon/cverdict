/**
 * Checks on an emitted output tree before it is published: every file parses, carries
 * schema_version/generated_at, fits its gzip budget, and the files agree with each other.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { gzipSync } from 'node:zlib';
import {
  PACKAGE_ECOSYSTEMS,
  ROW_COLS,
  SCHEMA_VERSION,
  SIGNAL_MIN_SCORE,
  TIERS,
  rowFromColumns,
  type BatchesFile,
  type KevFile,
  type MethodScore,
  type Meta,
  type PackagesFile,
  type ReceiptsFile,
  RECEIPT_METHODS,
  type Row,
  type Tier,
  type WokeFile,
  WAKE_KINDS,
} from '../../shared/contract';
import { ADVISORY_ID_RE, ATTRIBUTION, advisoryDatabase, packageKey } from '../../shared/packages';
import { CVE_ID_RE, shardOf } from '../../shared/shard';
import { COMPARATORS, parseEvent } from '../../shared/versions';
import { backtestProblems } from './backtest';
import { PATHS, SHARD_NAMES } from './emit/json';
import { BUDGETS } from './config';
import type { Logger } from './types';
import { asObject, type JsonObject } from './util/json';
import { formatBytes } from './util/log';

const FILE_BUDGETS: Readonly<Record<string, number>> = BUDGETS.gzipBytes;

const REQUIRED = [
  PATHS.meta,
  PATHS.signal,
  PATHS.index,
  PATHS.batches,
  PATHS.kev,
  PATHS.stats,
  PATHS.changes,
  PATHS.woke,
  PATHS.state,
  PATHS.receipts,
  PATHS.packages,
  PATHS.signalFeed,
  PATHS.kevFeed,
  PATHS.kevDueIcs,
  PATHS.wokeFeed,
  ...SHARD_NAMES.map(PATHS.shard),
];

export interface SizeRow {
  file: string;
  bytes: number;
  gzip: number;
  budget: number | null;
  status: 'ok' | 'near' | 'over' | 'fail';
}

export interface ValidationResult {
  ok: boolean;
  warnings: string[];
  errors: string[];
  sizes: SizeRow[];
  files: number;
}

function listFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else out.push(relative(root, p).split(sep).join('/'));
    }
  };
  walk(root);
  return out.sort();
}

const STATUS_ORDER: readonly SizeRow['status'][] = ['ok', 'near', 'over', 'fail'];

function budgetStatus(gzip: number, budget: number | null): SizeRow['status'] {
  if (budget === null) return 'ok';
  const ratio = gzip / budget;
  if (ratio > BUDGETS.failRatio) return 'fail';
  if (ratio > 1) return 'over';
  if (ratio > BUDGETS.warnRatio) return 'near';
  return 'ok';
}

/** Human-readable size table (shards are summarised in one line). */
export function formatSizeTable(sizes: readonly SizeRow[]): string {
  const shard = /^v1\/cve\//;
  const rows: [string, string, string, string, string][] = [];
  for (const s of sizes.filter((r) => !shard.test(r.file))) {
    rows.push([s.file, formatBytes(s.bytes), formatBytes(s.gzip), s.budget === null ? '—' : formatBytes(s.budget), s.status]);
  }
  const shards = sizes.filter((r) => shard.test(r.file));
  if (shards.length > 0) {
    const max = shards.reduce((a, b) => (b.gzip > a.gzip ? b : a));
    const worst = shards.reduce<SizeRow['status']>((w, r) => (STATUS_ORDER.indexOf(r.status) > STATUS_ORDER.indexOf(w) ? r.status : w), 'ok');
    rows.push([
      `v1/cve/*.json (${shards.length}, max ${max.file.slice(7)})`,
      formatBytes(shards.reduce((a, r) => a + r.bytes, 0)),
      `${formatBytes(shards.reduce((a, r) => a + r.gzip, 0))} (max ${formatBytes(max.gzip)})`,
      `${formatBytes(BUDGETS.shardGzipBytes)} each`,
      worst,
    ]);
  }
  const header: [string, string, string, string, string] = ['file', 'bytes', 'gzip', 'budget', 'status'];
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
  return [header, ...rows].map((r) => r.map((c, i) => (i === 0 ? c.padEnd(widths[i]) : c.padStart(widths[i]))).join('  ')).join('\n');
}

export function validateOutput(root: string, log?: Logger): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const files = listFiles(root);
  const present = new Set(files);
  const json = new Map<string, JsonObject>();
  const sizes: SizeRow[] = [];

  if (files.length > BUDGETS.maxFiles) errors.push(`${files.length} files emitted; the limit is ${BUDGETS.maxFiles}`);
  for (const p of REQUIRED) if (!present.has(p)) errors.push(`missing ${p}`);

  for (const file of files) {
    const buf = readFileSync(join(root, file));
    const gzip = gzipSync(buf).length;
    const budget = FILE_BUDGETS[file] ?? (file.startsWith('v1/cve/') ? BUDGETS.shardGzipBytes : null);
    const status = budgetStatus(gzip, budget);
    sizes.push({ file, bytes: buf.length, gzip, budget, status });
    if (status === 'fail') errors.push(`${file}: ${formatBytes(gzip)} gzip exceeds ${BUDGETS.failRatio * 100}% of its ${formatBytes(budget!)} budget`);
    else if (status === 'over') warnings.push(`${file}: ${formatBytes(gzip)} gzip is over its ${formatBytes(budget!)} budget`);
    else if (status === 'near') warnings.push(`${file}: ${formatBytes(gzip)} gzip is above ${BUDGETS.warnRatio * 100}% of its ${formatBytes(budget!)} budget`);

    if (!file.endsWith('.json')) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(buf.toString('utf8'));
    } catch (e) {
      errors.push(`${file}: invalid JSON (${(e as Error).message})`);
      continue;
    }
    const doc = asObject(parsed);
    if (!doc) {
      errors.push(`${file}: top level is not an object`);
      continue;
    }
    if (doc.schema_version !== SCHEMA_VERSION) errors.push(`${file}: schema_version is ${String(doc.schema_version)}, expected ${SCHEMA_VERSION}`);
    if (typeof doc.generated_at !== 'string' || Number.isNaN(Date.parse(doc.generated_at))) errors.push(`${file}: missing or invalid generated_at`);
    json.set(file, doc);
  }

  checkConsistency(json, errors, warnings);
  checkFeeds(root, present, errors);

  const result = { ok: errors.length === 0, warnings, errors, sizes, files: files.length };
  if (log) {
    for (const line of formatSizeTable(sizes).split('\n')) log.info(line);
    for (const w of warnings) log.warn(w);
    for (const e of errors) log.error(e);
  }
  return result;
}

/** Parse a RowTable, reporting structural problems; returns null when unusable. */
function readRows(file: string, doc: JsonObject | undefined, errors: string[]): Row[] | null {
  if (!doc) return null;
  const { cols, rows } = doc;
  if (!Array.isArray(cols) || cols.join() !== ROW_COLS.join()) {
    errors.push(`${file}: cols do not match ROW_COLS`);
    return null;
  }
  if (!Array.isArray(rows)) {
    errors.push(`${file}: rows is not an array`);
    return null;
  }
  const out: Row[] = [];
  const bad: string[] = [];
  for (const [i, values] of rows.entries()) {
    if (!Array.isArray(values) || values.length !== ROW_COLS.length) {
      bad.push(`row ${i} has the wrong shape`);
      continue;
    }
    const r = rowFromColumns(ROW_COLS, values);
    if (typeof r.id !== 'string' || !CVE_ID_RE.test(r.id)) bad.push(`row ${i} has an invalid id`);
    else if (!(TIERS as readonly string[]).includes(r.tier)) bad.push(`${r.id} has an invalid tier`);
    else out.push(r);
  }
  if (bad.length > 0) errors.push(`${file}: ${bad.length} bad rows (first: ${bad[0]})`);
  return out;
}

function checkConsistency(json: Map<string, JsonObject>, errors: string[], warnings: string[]): void {
  const index = readRows(PATHS.index, json.get(PATHS.index), errors);
  const signal = readRows(PATHS.signal, json.get(PATHS.signal), errors);

  const details = new Set<string>();
  for (const name of SHARD_NAMES) {
    const shard = json.get(PATHS.shard(name));
    if (!shard) continue;
    const items = asObject(shard.items);
    if (!items) {
      errors.push(`${PATHS.shard(name)}: items is not an object`);
      continue;
    }
    for (const [id, d] of Object.entries(items)) {
      if (shardOf(id) !== name) errors.push(`${id} is stored in shard ${name}, expected ${shardOf(id)}`);
      if (asObject(d)?.id !== id) errors.push(`${PATHS.shard(name)}: item ${id} has a mismatched id`);
      details.add(id);
    }
  }

  if (index) {
    const ids = new Set(index.map((r) => r.id));
    if (ids.size !== index.length) errors.push(`${PATHS.index}: duplicate ids`);
    const missing = index.filter((r) => !details.has(r.id));
    if (missing.length > 0) errors.push(`${missing.length} index rows have no detail shard entry (first: ${missing[0].id})`);

    if (signal) {
      const outside = signal.filter((r) => !ids.has(r.id));
      if (outside.length > 0) errors.push(`${outside.length} signal rows are not in the index (first: ${outside[0].id})`);
      const stray = signal.filter((r) => r.s < SIGNAL_MIN_SCORE && !r.x && !r.w);
      if (stray.length > 0) errors.push(`${stray.length} signal rows do not meet the signal rule (first: ${stray[0].id})`);
      const expected = index.filter((r) => r.s >= SIGNAL_MIN_SCORE || r.x || r.w).length;
      if (expected !== signal.length) errors.push(`signal has ${signal.length} rows, index implies ${expected}`);
    }

    const meta = json.get(PATHS.meta) as Meta | undefined;
    if (meta && asObject(meta.counts)) checkMeta(meta, index, json, errors, warnings);

    const batches = json.get(PATHS.batches) as BatchesFile | undefined;
    if (batches && Array.isArray(batches.batches)) {
      for (const b of batches.batches) {
        const sum = TIERS.reduce((a, t) => a + (b.by_tier?.[t] ?? 0), 0);
        if (sum !== b.count) errors.push(`batch ${b.id}: by_tier sums to ${sum}, count is ${b.count}`);
        const stray = (b.top ?? []).filter((r) => !ids.has(r.id));
        if (stray.length > 0) errors.push(`batch ${b.id}: top rows not in the index (first: ${stray[0].id})`);
      }
    }
  }

  checkWoke(json, details, index ? new Set(index.map((r) => r.id)) : null, errors);
  checkReceipts(json, errors);
  checkPackages(json, details, index, errors, warnings);

  const kev = json.get(PATHS.kev) as KevFile | undefined;
  if (kev && Array.isArray(kev.entries)) {
    const noDetail = kev.entries.filter((e) => !details.has(e.id));
    if (noDetail.length > 0) warnings.push(`${noDetail.length} kev.json entries have no CVE record in the shards (first: ${noDetail[0].id})`);
  }
}

/** woke.json: well-formed items, all published before the window, each with a detail that says so. */
function checkWoke(json: Map<string, JsonObject>, details: Set<string>, indexIds: Set<string> | null, errors: string[]): void {
  const woke = json.get(PATHS.woke) as WokeFile | undefined;
  if (woke) {
    if (!Array.isArray(woke.items)) {
      errors.push(`${PATHS.woke}: items is not an array`);
    } else {
      const bad: string[] = [];
      const cutoff = Date.parse(woke.published_before);
      for (const it of woke.items) {
        if (typeof it?.id !== 'string' || !CVE_ID_RE.test(it.id) || it.row?.id !== it.id) bad.push(`an item has an invalid id`);
        else if (!Array.isArray(it.signals) || it.signals.length === 0 || it.signals.some((s) => !WAKE_KINDS.includes(s.kind) || Number.isNaN(Date.parse(s.at)))) bad.push(`${it.id} has invalid signals`);
        else if (!(Date.parse(it.row.pub) < cutoff)) bad.push(`${it.id} was published in the window`);
        else if (indexIds?.has(it.id)) bad.push(`${it.id} is also in the index`);
        else if (!details.has(it.id)) bad.push(`${it.id} has no detail shard entry`);
      }
      if (bad.length > 0) errors.push(`${PATHS.woke}: ${bad.length} bad items (first: ${bad[0]})`);
      const ids = new Set(woke.items.map((i) => i.id));
      if (ids.size !== woke.items.length) errors.push(`${PATHS.woke}: duplicate ids`);
      for (const k of WAKE_KINDS) {
        const n = woke.items.filter((i) => Array.isArray(i.signals) && i.signals.some((s) => s.kind === k)).length;
        if (woke.counts?.[k] !== n) errors.push(`${PATHS.woke}: counts.${k} is ${woke.counts?.[k]}, items imply ${n}`);
      }
    }
  }
  const state = json.get(PATHS.state);
  if (state && (state.state_version !== 1 || !asObject(state.sections))) errors.push(`${PATHS.state}: not a state file (state_version 1 with sections)`);
}

/** One method's counts must add up: same_day + earlier = before ≤ n, and a lead only when before > 0. */
function badScore(m: MethodScore | undefined, n: number): boolean {
  if (!m) return true;
  const counts = [m.n, m.before, m.earlier, m.same_day];
  if (!counts.every((x) => Number.isInteger(x) && x >= 0)) return true;
  return m.n !== n || m.earlier + m.same_day !== m.before || m.before > m.n || (m.lead === null) !== (m.before === 0);
}

/** receipts.json: the figures agree with the per-CVE lists, the backtest is marked as hindsight. */
function checkReceipts(json: Map<string, JsonObject>, errors: string[]): void {
  const r = json.get(PATHS.receipts) as ReceiptsFile | undefined;
  if (!r) return;
  const err = (msg: string): void => void errors.push(`${PATHS.receipts}: ${msg}`);
  const f = r.forward;
  if (!f || !Array.isArray(f.items) || !Array.isArray(f.uncounted) || !Array.isArray(f.methods) || !Array.isArray(f.volume)) return err('forward is incomplete');
  if (!(Date.parse(f.since) <= Date.parse(f.last))) err('forward.since is after forward.last');
  if (f.eligible !== f.items.length || f.listed !== f.items.length + f.uncounted.length) err('forward counts do not match its lists');
  const sinceDay = f.since.slice(0, 10);
  const ids = [...f.items, ...f.uncounted].map((i) => i.id);
  if (new Set(ids).size !== ids.length) err('a CVE is listed twice');
  const bad = [...f.items, ...f.uncounted].find((i) => !CVE_ID_RE.test(i.id) || !(i.kev_added >= sinceDay));
  if (bad) err(`${bad.id} is not a KEV addition since ${sinceDay}`);
  for (const m of RECEIPT_METHODS) {
    const score = f.methods.find((x) => x.method === m);
    if (badScore(score, f.eligible)) err(`forward.methods.${m} does not add up`);
    const before = f.items.filter((i) => i.flags?.[m]?.outcome === 'earlier' || i.flags?.[m]?.outcome === 'same_day').length;
    if (score && score.before !== before) err(`forward.methods.${m}.before is ${score.before}, items imply ${before}`);
    const v = f.volume.find((x) => x.method === m);
    if (!v || v.flagged > v.n) err(`forward.volume.${m} is invalid`);
  }
  if (!f.gap_total || !Number.isInteger(f.gap_total.n) || f.gap_total.n < f.gaps.length || !(f.gap_total.hours >= 0)) err('forward.gap_total is invalid');
  if (r.backtest === null) return;
  for (const problem of backtestProblems(r.backtest)) err(problem);
}

/** What compactRecord writes: no whitespace, no control characters, at most 128 characters. */
const EVENT_RE = /^(?:(?:>=|<=|<)[^\s\u0000-\u001f\u007f-\u009f]{1,128}|\?[a-z_]{1,32}=[^\s\u0000-\u001f\u007f-\u009f]{0,128})$/;
const VERSION_RE = /^[^\s\u0000-\u001f\u007f-\u009f]{1,128}$/;

/**
 * packages.json: one source per ecosystem, packages only for ecosystems with a copy, every entry
 * well-formed with an advisory from a database the attribution lists (and the attribution is the
 * one in shared/packages.ts, notices included), package keys in packageKey() form, and exactly one
 * row per CVE named, equal to its index.json row and backed by a detail shard.
 */
function checkPackages(json: Map<string, JsonObject>, details: Set<string>, index: Row[] | null, errors: string[], warnings: string[]): void {
  const doc = json.get(PATHS.packages) as PackagesFile | undefined;
  if (!doc) return;
  const err = (msg: string): void => void errors.push(`${PATHS.packages}: ${msg}`);
  if (JSON.stringify(doc.attribution) !== JSON.stringify(ATTRIBUTION)) err('attribution does not match shared/packages.ts ATTRIBUTION');
  const attribution = Array.isArray(doc.attribution) ? doc.attribution : [];
  if (!Array.isArray(doc.sources) || doc.sources.map((s) => s?.ecosystem).join() !== PACKAGE_ECOSYSTEMS.join()) return err('sources must list every ecosystem once, in PACKAGE_ECOSYSTEMS order');
  for (const s of doc.sources) {
    if (typeof s.ok !== 'boolean' || typeof s.stale !== 'boolean' || !Number.isInteger(s.advisories) || !Number.isInteger(s.matched) || s.matched < 0 || s.matched > s.advisories) {
      err(`sources.${s.ecosystem} is invalid`);
    }
  }
  const packages = asObject(doc.packages);
  if (!packages) return err('packages is not an object');
  const okEcos = new Set(doc.sources.filter((s) => s.ok).map((s) => s.ecosystem));
  const named = new Set<string>();
  const bad: string[] = [];
  const unparsed = new Map<string, number>();
  for (const [eco, pkgs] of Object.entries(packages)) {
    if (!(PACKAGE_ECOSYSTEMS as readonly string[]).includes(eco) || !okEcos.has(eco as (typeof PACKAGE_ECOSYSTEMS)[number])) {
      err(`packages has ${eco}, which is not an ecosystem with a copy`);
      continue;
    }
    const e = eco as (typeof PACKAGE_ECOSYSTEMS)[number];
    const byKey = asObject(pkgs);
    if (!byKey) {
      err(`packages.${eco} is not an object`);
      continue;
    }
    for (const [key, entries] of Object.entries(byKey)) {
      if (packageKey(e, key) !== key) bad.push(`${eco} key "${key.slice(0, 60)}" is not in packageKey() form`);
      if (!Array.isArray(entries) || entries.length === 0) {
        bad.push(`${eco} ${key.slice(0, 60)} has no entries`);
        continue;
      }
      for (const entry of entries as unknown[]) {
        const [cve, advisory, ranges, versions] = Array.isArray(entry) ? entry : [];
        const where = `${eco} ${key.slice(0, 60)}`;
        if (!Array.isArray(entry) || entry.length < 3 || entry.length > 4) bad.push(`${where}: an entry has the wrong shape`);
        else if (typeof cve !== 'string' || !CVE_ID_RE.test(cve)) bad.push(`${where}: invalid CVE id`);
        else if (typeof advisory !== 'string' || !ADVISORY_ID_RE.test(advisory)) bad.push(`${where}: invalid advisory id`);
        else if (!advisoryDatabase(advisory, attribution)) bad.push(`${where}: ${advisory} is from a database the attribution does not list`);
        else if (!Array.isArray(ranges) || !ranges.every((r) => Array.isArray(r) && r.length > 0 && r.every((ev) => typeof ev === 'string' && EVENT_RE.test(ev)))) bad.push(`${where}: ${advisory} has a malformed range`);
        else if (versions !== undefined && !(Array.isArray(versions) && versions.length > 0 && versions.every((v) => typeof v === 'string' && VERSION_RE.test(v)))) bad.push(`${where}: ${advisory} has malformed versions`);
        else if (ranges.length === 0 && versions === undefined) bad.push(`${where}: ${advisory} has neither ranges nor versions`);
        else {
          named.add(cve);
          const c = COMPARATORS[e];
          const unreadable = (ranges as string[][]).filter((r) => r.some((ev) => {
            const p = parseEvent(ev);
            return !p || (p.op !== '?' && p.v !== '0' && c.parse(p.v) === null);
          })).length;
          if (unreadable > 0) unparsed.set(eco, (unparsed.get(eco) ?? 0) + unreadable);
        }
      }
    }
  }
  if (bad.length > 0) err(`${bad.length} bad entries (first: ${bad[0]})`);
  for (const [eco, n] of unparsed) warnings.push(`${PATHS.packages}: ${n} ${eco} ranges have a bound shared/versions.ts cannot compare (shown as "possibly affected")`);

  const rows = readRows(`${PATHS.packages} cves`, asObject(doc.cves) ?? undefined, errors);
  if (!rows) return;
  const rowIds = rows.map((r) => r.id);
  if (new Set(rowIds).size !== rowIds.length) err('cves has duplicate rows');
  const unnamed = rowIds.filter((id) => !named.has(id));
  if (unnamed.length > 0) err(`${unnamed.length} cves rows are not named in packages (first: ${unnamed[0]})`);
  const rowSet = new Set(rowIds);
  const missing = [...named].filter((id) => !rowSet.has(id));
  if (missing.length > 0) err(`${missing.length} CVEs named in packages have no row in cves (first: ${missing[0]})`);
  const noDetail = rowIds.filter((id) => !details.has(id));
  if (noDetail.length > 0) err(`${noDetail.length} cves rows have no detail shard entry (first: ${noDetail[0]})`);
  if (index) {
    const indexRows = new Map(index.map((r) => [r.id, JSON.stringify(ROW_COLS.map((c) => r[c]))]));
    const differ = rows.filter((r) => indexRows.has(r.id) && indexRows.get(r.id) !== JSON.stringify(ROW_COLS.map((c) => r[c])));
    if (differ.length > 0) err(`${differ.length} cves rows differ from their index.json row (first: ${differ[0].id})`);
  }
}

function checkMeta(meta: Meta, index: Row[], json: Map<string, JsonObject>, errors: string[], warnings: string[]): void {
  const c = meta.counts;
  const byTier = Object.fromEntries(TIERS.map((t) => [t, 0])) as Record<Tier, number>;
  for (const r of index) byTier[r.tier]++;
  if (c.window_published !== index.length) errors.push(`meta.counts.window_published is ${c.window_published}, index has ${index.length} rows`);
  for (const t of TIERS) {
    if (c.window_by_tier?.[t] !== byTier[t]) errors.push(`meta.counts.window_by_tier.${t} is ${c.window_by_tier?.[t]}, index has ${byTier[t]}`);
  }
  if (c.window_passed !== byTier.exploited + byTier.likely) errors.push(`meta.counts.window_passed is ${c.window_passed}, index implies ${byTier.exploited + byTier.likely}`);
  if (c.published_24h > c.published_7d || c.published_7d > c.window_published) errors.push('meta.counts: published_24h ≤ published_7d ≤ window_published does not hold');
  if (c.passed_24h > c.published_24h || c.passed_7d > c.published_7d) errors.push('meta.counts: passed counts exceed published counts');
  const ai = index.filter((r) => r.ai).length;
  if (c.ai_credited_window !== ai) errors.push(`meta.counts.ai_credited_window is ${c.ai_credited_window}, index has ${ai}`);
  const batches = json.get(PATHS.batches) as BatchesFile | undefined;
  if (batches && Array.isArray(batches.batches) && c.batches_window !== batches.batches.length) {
    errors.push(`meta.counts.batches_window is ${c.batches_window}, batches.json has ${batches.batches.length}`);
  }
  const undefinedCounts = Object.keys(c).filter((k) => !meta.definitions?.[k]);
  if (undefinedCounts.length > 0) warnings.push(`meta.definitions is missing: ${undefinedCounts.join(', ')}`);
  if (!Array.isArray(meta.sources) || meta.sources.length === 0) errors.push('meta.sources is empty');
  else for (const s of meta.sources.filter((s) => s.stale || !s.ok)) warnings.push(`source ${s.id} is ${s.ok ? 'stale' : 'down'}${s.error ? `: ${s.error}` : ''}`);
}

function checkFeeds(root: string, present: Set<string>, errors: string[]): void {
  for (const feed of [PATHS.signalFeed, PATHS.kevFeed, PATHS.wokeFeed]) {
    if (!present.has(feed)) continue;
    const xml = readFileSync(join(root, feed), 'utf8');
    if (!xml.startsWith('<?xml') || !/<feed xmlns="http:\/\/www\.w3\.org\/2005\/Atom">/.test(xml) || !xml.trimEnd().endsWith('</feed>')) {
      errors.push(`${feed}: not an Atom document`);
    }
    if ((xml.match(/<entry>/g) ?? []).length !== (xml.match(/<\/entry>/g) ?? []).length) errors.push(`${feed}: unbalanced <entry> elements`);
  }
  if (present.has(PATHS.kevDueIcs)) {
    const ics = readFileSync(join(root, PATHS.kevDueIcs), 'utf8');
    if (!ics.startsWith('BEGIN:VCALENDAR\r\n') || !ics.endsWith('END:VCALENDAR\r\n')) errors.push(`${PATHS.kevDueIcs}: not an iCalendar object`);
    if (/[^\r]\n/.test(ics)) errors.push(`${PATHS.kevDueIcs}: bare LF line ending`);
    const lines = ics.split('\r\n');
    const long = lines.filter((l) => Buffer.byteLength(l, 'utf8') > 75);
    if (long.length > 0) errors.push(`${PATHS.kevDueIcs}: ${long.length} lines longer than 75 octets`);
    const count = (l: string) => lines.filter((x) => x === l).length;
    if (count('BEGIN:VEVENT') !== count('END:VEVENT')) errors.push(`${PATHS.kevDueIcs}: unbalanced VEVENTs`);
  }
}
