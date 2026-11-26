/**
 * Checks on an emitted output tree before it is published: every file parses, carries
 * schema_version/generated_at, fits its gzip budget, and the files agree with each other.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { gzipSync } from 'node:zlib';
import {
  NEW_EXPLOITED_HOURS,
  NEW_EXPLOITED_LIST_MAX,
  NEW_EXPLOITED_VIA,
  PACKAGE_ECOSYSTEMS,
  ROW_COLS,
  SCHEMA_VERSION,
  KEV_LAG_BUCKETS,
  SEVERITY_BANDS,
  SURGE_TOP_CNAS,
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
import { compareEvents } from '../../shared/atom';
import { backtestProblems } from './backtest';
import { parseItem } from './events';
import { PATHS, SHARD_NAMES } from './emit/json';
import { OLDER_TITLE_MAX } from './packages';
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
  PATHS.events,
  PATHS.woke,
  PATHS.state,
  PATHS.receipts,
  PATHS.packages,
  PATHS.signalFeed,
  PATHS.kevFeed,
  PATHS.kevDueIcs,
  PATHS.wokeFeed,
  PATHS.eventsFeed,
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

/** Signals that can make a CVE published before the window newly exploited: a dated catalog listing. */
const LISTING_VIA: readonly string[] = ['CISA KEV', 'EU KEV', 'CIRCL'];

/**
 * stats.json hourly.new_exploited (optional): [hour, count] pairs in range, ascending, never more than the hour's
 * exploited count. hourly.new_exploited_cves (optional): unique CVEs, signal inside the 72 hours before
 * generated_at, newest first, at most the cap. A row with an `hour` is an Exploited CVE of the index in the column
 * of its publication hour, and those rows tally per hour to the pairs (exactly, below the cap). A row without one
 * is a CVE published before the window: no `hour`, a `published` day before hourly.start, a catalog listing day as
 * its signal, and not in the index. hourly.new_exploited_total (optional): the list's length before the cap, so
 * equal to it below the cap, never less than it or than the pairs' sum.
 */
function checkNewExploited(json: Map<string, JsonObject>, index: readonly Row[] | null, errors: string[]): void {
  const stats = json.get(PATHS.stats);
  const hourly = asObject(stats?.hourly);
  if (!hourly) return;
  const counts = Array.isArray(hourly.counts) ? hourly.counts : [];
  const pairs = new Map<number, number>();
  if (hourly.new_exploited !== undefined) {
    if (!Array.isArray(hourly.new_exploited)) {
      errors.push(`${PATHS.stats}: hourly.new_exploited is not an array`);
      return;
    }
    let prev = -1;
    for (const p of hourly.new_exploited) {
      const [h, n] = Array.isArray(p) ? p : [];
      const exploited = Array.isArray(counts[h as number]) ? Number((counts[h as number] as unknown[])[0]) : -1;
      if (!Number.isInteger(h) || !Number.isInteger(n) || (n as number) < 1 || (h as number) <= prev || (n as number) > exploited) {
        errors.push(`${PATHS.stats}: hourly.new_exploited has a bad entry ${JSON.stringify(p)}`);
        return;
      }
      prev = h as number;
      pairs.set(h as number, n as number);
    }
  }

  const list = hourly.new_exploited_cves;
  const total = hourly.new_exploited_total;
  const bad = (why: string) => errors.push(`${PATHS.stats}: ${why}`);
  if (total !== undefined) {
    if (!Number.isInteger(total) || (total as number) < 0) return void bad(`hourly.new_exploited_total is not a count: ${JSON.stringify(total)}`);
    if (list === undefined) return void bad('hourly.new_exploited_total is present without hourly.new_exploited_cves');
  }
  if (list === undefined) return;
  const badList = (why: string) => bad(`hourly.new_exploited_cves ${why}`);
  if (!Array.isArray(list)) return void badList('is not an array');
  if (hourly.new_exploited === undefined) return void badList('is present without hourly.new_exploited');
  if (list.length > NEW_EXPLOITED_LIST_MAX) return void badList(`has ${list.length} entries, the cap is ${NEW_EXPLOITED_LIST_MAX}`);
  const generated = typeof stats?.generated_at === 'string' ? Date.parse(stats.generated_at) : NaN;
  const start = typeof hourly.start === 'string' ? Date.parse(hourly.start) : NaN;
  const rows = index ? new Map(index.map((r) => [r.id, r])) : null;
  const seen = new Set<string>();
  const tally = new Map<number, number>();
  let prevMs = Infinity;
  for (const item of list) {
    const c = asObject(item);
    const id = c?.id;
    const h = c?.hour as number;
    const day = typeof c?.at === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(c.at);
    const ms = typeof c?.at === 'string' ? Date.parse(day ? `${c.at}T00:00:00Z` : c.at) : NaN;
    const common =
      typeof id === 'string' &&
      CVE_ID_RE.test(id) &&
      typeof c?.title === 'string' &&
      c.title.length > 0 &&
      c.title.length <= 80 &&
      (NEW_EXPLOITED_VIA as readonly unknown[]).includes(c.via) &&
      ms <= generated &&
      ms >= generated - NEW_EXPLOITED_HOURS * 3_600_000;
    if (!common) return void badList(`has a bad entry ${JSON.stringify(item)}`);
    if (seen.has(id)) return void badList(`lists ${id} twice`);
    if (ms > prevMs) return void badList(`is not newest first at ${id}`);
    if (c.hour === undefined) {
      // Published before the window: not on the chart, so no hour; a catalog listing is its signal.
      const pub = typeof c.published === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(c.published) ? Date.parse(`${c.published}T00:00:00Z`) : NaN;
      if (!(pub < start) || !day || !LISTING_VIA.includes(c.via as string)) return void badList(`has a bad entry from before the window ${JSON.stringify(item)}`);
      if (rows?.has(id)) return void badList(`lists ${id} without an hour, but it is in the index`);
    } else {
      const exploited = Array.isArray(counts[h]) ? Number((counts[h] as unknown[])[0]) : 0;
      if (!Number.isInteger(h) || exploited <= 0 || c.published !== undefined) return void badList(`has a bad entry ${JSON.stringify(item)}`);
      const row = rows?.get(id);
      if (rows && (!row || row.tier !== 'exploited')) return void badList(`lists ${id}, which is not an Exploited CVE in the index`);
      if (row && Math.floor((Date.parse(row.pub) - start) / 3_600_000) !== h) return void badList(`puts ${id} in hour ${h}, not its publication hour`);
      tally.set(h, (tally.get(h) ?? 0) + 1);
    }
    seen.add(id);
    prevMs = ms;
  }
  // At the cap, older ones are left out of the list but still counted.
  const full = list.length === NEW_EXPLOITED_LIST_MAX;
  for (const h of new Set([...pairs.keys(), ...tally.keys()])) {
    const t = tally.get(h) ?? 0;
    const p = pairs.get(h) ?? 0;
    if (full ? t > p : t !== p) return void badList(`has ${t} in hour ${h}, hourly.new_exploited has ${p}`);
  }
  if (typeof total === 'number') {
    const charted = [...pairs.values()].reduce((a, n) => a + n, 0);
    if (full ? total < list.length : total !== list.length) return void bad(`hourly.new_exploited_total is ${total}, the list has ${list.length}`);
    if (total < charted) return void bad(`hourly.new_exploited_total is ${total}, less than the ${charted} in hourly.new_exploited`);
  }
}

/**
 * stats.json kev_lag (optional): consecutive years, oldest first, ending at generated_at's year (the only partial
 * one); each row's buckets are KEV_LAG_BUCKETS.length whole counts summing to `count`; the median is null exactly
 * when the count is 0, else a whole or half day. Monthly KEV additions bound each year's count from above.
 */
export function checkKevLag(stats: JsonObject | undefined, errors: string[]): void {
  const rows = stats?.kev_lag;
  if (rows === undefined) return;
  const bad = (why: string) => errors.push(`${PATHS.stats}: kev_lag ${why}`);
  if (!Array.isArray(rows)) return void bad('is not an array');
  if (!rows.length) return;
  const generated = typeof stats?.generated_at === 'string' ? Number(stats.generated_at.slice(0, 4)) : NaN;
  const added = new Map<number, number>();
  for (const m of Array.isArray(stats?.monthly) ? stats.monthly : []) {
    const o = asObject(m);
    if (typeof o?.month === 'string' && typeof o.kev_added === 'number') added.set(Number(o.month.slice(0, 4)), (added.get(Number(o.month.slice(0, 4))) ?? 0) + o.kev_added);
  }
  let prev: number | null = null;
  for (const item of rows) {
    const r = asObject(item);
    const year = r?.year as number;
    const count = r?.count as number;
    const buckets = r?.buckets;
    const med = r?.median_days;
    const shape =
      Number.isInteger(year) &&
      Number.isInteger(count) &&
      count >= 0 &&
      Array.isArray(buckets) &&
      buckets.length === KEV_LAG_BUCKETS.length &&
      buckets.every((v) => Number.isInteger(v) && v >= 0) &&
      (count === 0 ? med === null : typeof med === 'number' && Number.isInteger(med * 2)) &&
      r?.partial === (year === generated);
    if (!shape) return void bad(`has a bad row ${JSON.stringify(item)}`);
    if (prev !== null && year !== prev + 1) return void bad(`skips or repeats a year at ${year}`);
    prev = year;
    const sum = (buckets as number[]).reduce((a, v) => a + v, 0);
    if (sum !== count) return void bad(`${year}: buckets sum to ${sum}, count is ${count}`);
    if (added.size && count > (added.get(year) ?? 0)) return void bad(`${year}: count ${count} is more than the ${added.get(year) ?? 0} KEV additions in monthly`);
  }
  if (prev !== generated) bad(`ends at ${prev}, not at generated_at's year ${generated}`);
}

/** A listed CNA's count in month index `m` and band `k`, 0 outside its rows. */
function cnaBand(c: JsonObject | null, m: number, k: number): number {
  const rows = c?.severity as number[][];
  return rows[m - (c?.from as number)]?.[k] ?? 0;
}

/**
 * surge.json (optional; older data has none): band rows of five whole counts, one per month from `start` to
 * generated_at's month; at most SURGE_TOP_CNAS distinct CNAs whose rows fit the months and never add up to more
 * than the month's band; KEV cells in range, sorted, unique, positive and within their month, CNA and band. From
 * the same run as stats.json, each month's bands sum to its published count there.
 */
export function checkSurge(surge: JsonObject | undefined, stats: JsonObject | undefined, errors: string[]): void {
  if (!surge) return;
  const bad = (why: string) => errors.push(`${PATHS.surge}: ${why}`);
  const isRow = (r: unknown): r is number[] => Array.isArray(r) && r.length === SEVERITY_BANDS.length && r.every((v) => Number.isInteger(v) && v >= 0);
  const sev = surge.severity;
  const generated = typeof surge.generated_at === 'string' ? surge.generated_at : '';
  if (surge.start !== '1999-01') return void bad(`start is ${JSON.stringify(surge.start)}, expected "1999-01"`);
  const months = Number(generated.slice(0, 4)) * 12 + Number(generated.slice(5, 7)) - (1999 * 12 + 1) + 1;
  if (!Array.isArray(sev) || sev.length !== months) return void bad(`severity has ${Array.isArray(sev) ? sev.length : 'no'} rows, expected ${months}`);
  const monthly = stats && stats.generated_at === surge.generated_at && Array.isArray(stats.monthly) ? stats.monthly : null;
  for (let i = 0; i < sev.length; i++) {
    const row = sev[i];
    if (!isRow(row)) return void bad(`severity[${i}] is not five whole counts`);
    const published = monthly ? asObject(monthly[i])?.published : undefined;
    const sum = row.reduce((a, v) => a + v, 0);
    if (monthly && sum !== published) return void bad(`severity[${i}] sums to ${sum}, stats.json monthly says ${String(published)}`);
  }
  const cnas = surge.cnas;
  if (!Array.isArray(cnas) || cnas.length > SURGE_TOP_CNAS) return void bad(`cnas is not a list of at most ${SURGE_TOP_CNAS}`);
  const names = new Set<string>();
  const used = sev.map(() => SEVERITY_BANDS.map(() => 0));
  for (const item of cnas) {
    const c = asObject(item);
    const name = c?.cna;
    const from = c?.from;
    const rows = c?.severity;
    if (typeof name !== 'string' || !name || names.has(name)) return void bad(`cnas has a missing or repeated name ${JSON.stringify(name)}`);
    names.add(name);
    if (!Number.isInteger(from) || (from as number) < 0 || !Array.isArray(rows) || (from as number) + rows.length > sev.length) return void bad(`cnas ${name} does not fit the months`);
    for (let j = 0; j < rows.length; j++) {
      const r = rows[j];
      const i = (from as number) + j;
      if (!isRow(r)) return void bad(`cnas ${name} month ${i} is not five whole counts`);
      for (let k = 0; k < r.length; k++) {
        used[i][k] += r[k];
        if (used[i][k] > (sev[i] as number[])[k]) return void bad(`cnas add up to more than month ${i} has in band ${k}`);
      }
    }
  }
  const kev = surge.kev;
  if (!Array.isArray(kev)) return void bad('kev is not an array');
  let prev = '';
  for (const cell of kev) {
    const [m, c, k, n] = Array.isArray(cell) && cell.length === 4 ? (cell as number[]) : [];
    const shape = [m, c, k, n].every(Number.isInteger) && m >= 0 && m < sev.length && c >= -1 && c < cnas.length && k >= 0 && k < SEVERITY_BANDS.length && n > 0;
    if (!shape) return void bad(`kev has a bad cell ${JSON.stringify(cell)}`);
    const key = [m, c + 1, k].map((v) => String(v).padStart(6, '0')).join('|');
    if (key <= prev) return void bad(`kev is not sorted by month, CNA and band at ${JSON.stringify(cell)}`);
    prev = key;
    const room = c < 0 ? (sev[m] as number[])[k] - used[m][k] : cnaBand(asObject(cnas[c]), m, k);
    if (n > room) return void bad(`kev cell ${JSON.stringify(cell)} is more than its month, CNA and band hold`);
  }
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
  checkNewExploited(json, index, errors);
  checkSurge(json.get(PATHS.surge), json.get(PATHS.stats), errors);
  checkKevLag(json.get(PATHS.stats), errors);
  checkReceipts(json, errors);
  checkEvents(json, errors);
  checkPackages(json, details, index, errors, warnings);

  const kev = json.get(PATHS.kev) as KevFile | undefined;
  if (kev && Array.isArray(kev.entries)) {
    const noDetail = kev.entries.filter((e) => !details.has(e.id));
    if (noDetail.length > 0) warnings.push(`${noDetail.length} kev.json entries have no CVE record in the shards (first: ${noDetail[0].id})`);
  }
}

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * events.json: every item well-formed with the id its fields imply (parseItem), ids unique, newest
 * first in the file's order, every `at` inside [generated_at - days, generated_at], no more than
 * max_items, and catalog snapshots with a 64-hex-digit hash.
 */
export function checkEvents(json: Map<string, JsonObject>, errors: string[]): void {
  const doc = json.get(PATHS.events);
  if (!doc) return;
  const err = (msg: string): void => void errors.push(`${PATHS.events}: ${msg}`);
  if (!Array.isArray(doc.items)) return err('items is not an array');
  if (!Number.isInteger(doc.days) || (doc.days as number) < 1) err('days is not a positive integer');
  if (!Number.isInteger(doc.max_items) || doc.items.length > (doc.max_items as number)) err(`${doc.items.length} items, max_items is ${String(doc.max_items)}`);
  if (!(doc.previous_at === null || (typeof doc.previous_at === 'string' && Number.isFinite(Date.parse(doc.previous_at))))) err('previous_at is not a date or null');
  const catalogs = asObject(doc.catalogs);
  if (!catalogs) err('catalogs is not an object');
  for (const name of ['kev', 'eu_kev']) {
    const c = catalogs?.[name];
    if (c === null) continue;
    const o = asObject(c);
    if (!o || typeof o.ids_sha256 !== 'string' || !HEX64.test(o.ids_sha256) || !Number.isInteger(o.count) || (o.count as number) < 1) err(`catalogs.${name} is not a snapshot`);
  }
  const end = Date.parse(String(doc.generated_at));
  const start = end - (Number(doc.days) || 0) * 86_400_000;
  const items = doc.items.map(parseItem);
  const bad = doc.items.filter((_, i) => items[i] === null);
  if (bad.length) err(`${bad.length} bad items (first: ${JSON.stringify(bad[0]).slice(0, 200)})`);
  const ok = items.filter((i) => i !== null);
  if (new Set(ok.map((i) => i.id)).size !== ok.length) err('duplicate ids');
  const outside = ok.filter((i) => !(Date.parse(i.at) >= start && Date.parse(i.at) <= end));
  if (outside.length) err(`${outside.length} items dated outside the last ${String(doc.days)} days (first: ${outside[0].id} at ${outside[0].at})`);
  for (let i = 1; i < ok.length; i++) {
    if (compareEvents(ok[i - 1], ok[i]) > 0) {
      err(`items are not newest first (${ok[i - 1].id} before ${ok[i].id})`);
      break;
    }
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
/**
 * packages.json, then packages-older.json (both optional). The first holds tracked CVEs, each with a
 * detail shard; the second every other CVE an advisory names, none with a detail shard, none in the
 * first file, every one published before the window. Both share the same shape and entry rules.
 */
function checkPackages(json: Map<string, JsonObject>, details: Set<string>, index: Row[] | null, errors: string[], warnings: string[]): void {
  const tracked = checkPackagesDoc(PATHS.packages, json.get(PATHS.packages) as PackagesFile | undefined, details, true, index, errors, warnings);
  const older = checkPackagesDoc(PATHS.packagesOlder, json.get(PATHS.packagesOlder) as PackagesFile | undefined, details, false, null, errors, warnings);
  if (!older) return;
  const both = tracked ? older.filter((r) => tracked.has(r.id)) : [];
  if (both.length > 0) errors.push(`${PATHS.packagesOlder}: ${both.length} rows are also in ${PATHS.packages} (first: ${both[0].id})`);
  const start = (json.get(PATHS.meta) as Meta | undefined)?.window?.from;
  const recent = start ? older.filter((r) => Date.parse(r.pub) >= Date.parse(start)) : [];
  if (recent.length > 0) errors.push(`${PATHS.packagesOlder}: ${recent.length} rows are published in the window (first: ${recent[0].id})`);
  const chips = older.filter((r) => r.c.length > 0 || r.r.length > 0 || r.t.length > OLDER_TITLE_MAX);
  if (chips.length > 0) errors.push(`${PATHS.packagesOlder}: ${chips.length} rows are not slim (first: ${chips[0].id})`);
}

/** One package file; returns its row IDs (tracked) or rows (older), or null when it is absent or unreadable. */
function checkPackagesDoc<T extends boolean>(
  path: string,
  doc: PackagesFile | undefined,
  details: Set<string>,
  withDetail: T,
  index: Row[] | null,
  errors: string[],
  warnings: string[],
): (T extends true ? Set<string> : Row[]) | null {
  type Out = T extends true ? Set<string> : Row[];
  if (!doc) return null;
  const err = (msg: string): null => {
    errors.push(`${path}: ${msg}`);
    return null;
  };
  if (JSON.stringify(doc.attribution) !== JSON.stringify(ATTRIBUTION)) err('attribution does not match shared/packages.ts ATTRIBUTION');
  const attribution = Array.isArray(doc.attribution) ? doc.attribution : [];
  if (!Array.isArray(doc.sources) || doc.sources.map((s) => s?.ecosystem).join() !== PACKAGE_ECOSYSTEMS.join()) return err('sources must list every ecosystem once, in PACKAGE_ECOSYSTEMS order');
  for (const s of doc.sources) {
    if (typeof s.ok !== 'boolean' || typeof s.stale !== 'boolean' || !Number.isInteger(s.advisories) || !Number.isInteger(s.matched) || s.matched < 0 || s.matched > s.advisories) {
      err(`sources.${s.ecosystem} is invalid`);
    }
  }
  const distinct = asObject(doc.distinct) as PackagesFile['distinct'] | null;
  const sum = (k: 'advisories' | 'matched') => doc.sources.reduce((n, s) => n + (s.ok ? s[k] : 0), 0);
  if (!distinct || !Number.isInteger(distinct.advisories) || !Number.isInteger(distinct.matched) || distinct.matched < 0 || distinct.matched > distinct.advisories) err('distinct is invalid');
  else if (distinct.advisories > sum('advisories') || distinct.matched > sum('matched')) err('distinct counts more advisories than sources[]');
  const packages = asObject(doc.packages);
  if (!packages) return err('packages is not an object');
  const okEcos = new Set(doc.sources.filter((s) => s.ok).map((s) => s.ecosystem));
  const named = new Set<string>();
  const advisoryIds = new Set<string>();
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
          advisoryIds.add(advisory);
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
  else if (distinct && distinct.matched !== advisoryIds.size) err(`distinct.matched is ${distinct.matched}, but packages holds ${advisoryIds.size} advisories`);
  for (const [eco, n] of unparsed) warnings.push(`${path}: ${n} ${eco} ranges have a bound shared/versions.ts cannot compare (shown as "possibly affected")`);

  const rows = readRows(`${path} cves`, asObject(doc.cves) ?? undefined, errors);
  if (!rows) return null;
  const rowIds = rows.map((r) => r.id);
  if (new Set(rowIds).size !== rowIds.length) err('cves has duplicate rows');
  const unnamed = rowIds.filter((id) => !named.has(id));
  if (unnamed.length > 0) err(`${unnamed.length} cves rows are not named in packages (first: ${unnamed[0]})`);
  const rowSet = new Set(rowIds);
  const missing = [...named].filter((id) => !rowSet.has(id));
  if (missing.length > 0) err(`${missing.length} CVEs named in packages have no row in cves (first: ${missing[0]})`);
  if (withDetail) {
    const noDetail = rowIds.filter((id) => !details.has(id));
    if (noDetail.length > 0) err(`${noDetail.length} cves rows have no detail shard entry (first: ${noDetail[0]})`);
  } else {
    const detailed = rowIds.filter((id) => details.has(id));
    if (detailed.length > 0) err(`${detailed.length} cves rows have a detail shard entry, so belong in ${PATHS.packages} (first: ${detailed[0]})`);
  }
  if (index) {
    const indexRows = new Map(index.map((r) => [r.id, JSON.stringify(ROW_COLS.map((c) => r[c]))]));
    const differ = rows.filter((r) => indexRows.has(r.id) && indexRows.get(r.id) !== JSON.stringify(ROW_COLS.map((c) => r[c])));
    if (differ.length > 0) err(`${differ.length} cves rows differ from their index.json row (first: ${differ[0].id})`);
  }
  return (withDetail ? rowSet : rows) as Out;
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
  for (const feed of [PATHS.signalFeed, PATHS.kevFeed, PATHS.wokeFeed, PATHS.eventsFeed]) {
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
