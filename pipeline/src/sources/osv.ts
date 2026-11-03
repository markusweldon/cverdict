/**
 * OSV.dev advisories for v1/packages.json: a compact mirror of the npm, PyPI, Maven, Go,
 * crates.io, RubyGems, Packagist and NuGet records that name a CVE.
 *
 * Per ecosystem, every run: a full sync from `<eco>/all.zip` when there is no copy or the copy's
 * full sync is 7 days old (conditional on its ETag); otherwise an incremental sync that reads the
 * head of `<eco>/modified_id.csv` (newest first) with Range requests down to the cursor, and
 * fetches each changed `<eco>/<id>.json`. A rejected full dump is downloaded again at most once a
 * day; meanwhile the copy keeps getting incremental updates. The mirror lives in `<cache>/sources/` (the directory
 * refresh.yml already caches). Each ecosystem fails on its own and falls back to its cached copy.
 *
 * Everything downloaded is untrusted: byte caps on every response, a redirect host check, advisory
 * IDs checked against a pattern before they become URLs and against the fetched record after,
 * only advisory databases with a known licence (ATTRIBUTION in shared/packages.ts), per-field
 * validation and caps, and the same validation again when the mirror is read back from the cache.
 *
 * OSV never feeds a score, chip or unknown: its status goes into meta.sources for health only.
 */
import { randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { PACKAGE_ECOSYSTEMS, type PackageEcosystem, type SourceStatus } from '../../../shared/contract';
import { ADVISORY_ID_RE, advisoryDatabase, advisoryPrefix } from '../../../shared/packages';
import { CVE_ID_RE } from '../../../shared/shard';
import { extraVersions } from '../../../shared/versions';
import { OSV, type OsvConfig, type SanityLimits } from '../config';
import type { Logger } from '../types';
import { describe, FetchRejected, readCapped, type HttpClient } from '../util/http';
import { formatBytes } from '../util/log';
import { ZipReader } from '../util/zip';
import { SanityError } from './source';

/** One affected package of an advisory: [OSV package name, ranges as event strings, extra versions?]. */
export type OsvAffected = [name: string, ranges: string[][], extra?: string[]];
/** One advisory: [id, modified, CVE IDs, affected packages of this ecosystem]. */
export type OsvLite = [id: string, modified: string, cves: string[], affected: OsvAffected[]];

/** The copy of one ecosystem. */
export interface OsvCopy {
  /** When all.zip was last read (or confirmed unchanged). */
  full_sync_at: string;
  /** For If-None-Match on the next full sync. */
  zip_etag: string | null;
  /** Newest modified_id.csv time applied. */
  cursor: string | null;
  /** Last successful contact with OSV.dev for this ecosystem. */
  fetched_at: string;
  /** When a due full sync last failed, and why; cleared by the next full sync that succeeds. */
  full_failed_at?: string;
  full_error?: string;
  /** Sorted by id. */
  records: OsvLite[];
}

export interface OsvMirror {
  version: 1;
  ecosystems: Partial<Record<PackageEcosystem, OsvCopy>>;
  /** Since when each ecosystem without a copy has had none, so a missing one ages like a stale one. */
  missing?: Partial<Record<PackageEcosystem, string>>;
}

/** Health of one ecosystem's copy this run (PackageSourceStatus without `matched`). */
export interface OsvEcosystemStatus {
  ok: boolean;
  stale: boolean;
  fetched_at: string | null;
  modified: string | null;
  advisories: number;
  error: string | null;
  /** Without a copy: since when (the mirror's `missing`). */
  missing_since?: string | null;
}

export interface OsvData {
  mirror: OsvMirror;
  statuses: Record<PackageEcosystem, OsvEcosystemStatus>;
}

/** No copy of anything (tests, and runs that never loaded OSV). */
export function emptyOsvData(error = 'not loaded'): OsvData {
  const statuses = Object.fromEntries(
    PACKAGE_ECOSYSTEMS.map((eco) => [eco, { ok: false, stale: true, fetched_at: null, modified: null, advisories: 0, error }]),
  ) as Record<PackageEcosystem, OsvEcosystemStatus>;
  return { mirror: { version: 1, ecosystems: {} }, statuses };
}

export interface OsvDeps {
  http: HttpClient;
  cacheDir: string;
  offline: boolean;
  log: Logger;
  limits: SanityLimits;
  /** Read `<osvDir>/<eco>.zip` instead of downloading (local development, reproducible runs). */
  osvDir?: string;
  signal?: AbortSignal;
  /** Wall clock (ms) for ages and fetched_at; deliberately not the run's frozen `now`. */
  clock?: () => number;
  /** Where all.zip downloads go while they are read; never the cache directory. */
  tmpDir?: string;
  /** Overrides for tests. */
  config?: Partial<OsvConfig>;
}

type Config = OsvConfig;

/** Counters shared by one run, for one warning line each. */
interface Counters {
  /** Advisory prefixes outside ATTRIBUTION, skipped. */
  prefixes: Map<string, number>;
  malformed: number;
}

// ── Record validation and compaction ──

const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const isVersionText = (v: unknown): v is string => typeof v === 'string' && v.length >= 1 && v.length <= 128 && !/\s/.test(v) && !CONTROL.test(v);
/** A bound that reads back unambiguously after its event prefix. */
const isBound = (v: unknown): v is string => isVersionText(v) && !/^[<>=?]/.test(v);
const isPackageName = (v: unknown): v is string => typeof v === 'string' && v.length >= 1 && v.length <= OSV.maxNameLength && !CONTROL.test(v);
const isTime = (v: unknown): v is string => typeof v === 'string' && v.length <= 40 && !Number.isNaN(Date.parse(v));
const EVENT_OPS: Readonly<Record<string, string>> = { introduced: '>=', fixed: '<', last_affected: '<=' };
const EVENT_RE = /^(?:(?:>=|<=|<)[^\s<>=?][^\s]{0,127}|\?[a-z_]{1,32}=[^\s]{0,128})$/;

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** One OSV range as event strings; null for range types we do not read (GIT). */
function compactRange(range: unknown): string[] | null {
  const r = asRecord(range);
  if (!r || (r.type !== 'SEMVER' && r.type !== 'ECOSYSTEM')) return null;
  const events = Array.isArray(r.events) ? r.events : [];
  if (events.length > OSV.maxEvents) return ['?events=capped'];
  const out: string[] = [];
  for (const ev of events) {
    const e = asRecord(ev);
    const entries = e ? Object.entries(e) : [];
    if (entries.length !== 1) {
      out.push('?invalid=');
      continue;
    }
    const [kind, value] = entries[0];
    const op = Object.hasOwn(EVENT_OPS, kind) ? EVENT_OPS[kind] : null;
    if (op && isBound(value)) out.push(op + value);
    else if (op) out.push('?invalid=');
    else out.push(`?${/^[a-z_]{1,32}$/.test(kind) ? kind : 'unknown'}=${isVersionText(value) ? value : ''}`);
  }
  return out.length > 0 ? out : ['?invalid='];
}

/**
 * Validate and compact one OSV record for one ecosystem, or null when it has nothing to publish:
 * withdrawn, no CVE alias, no package in this ecosystem, a database outside ATTRIBUTION, or
 * malformed. Ranges of the same package across several `affected[]` objects are merged.
 */
export function compactRecord(json: unknown, eco: PackageEcosystem, counters?: Counters): OsvLite | null {
  const d = asRecord(json);
  const id = d?.id;
  if (!d || typeof id !== 'string' || !ADVISORY_ID_RE.test(id) || !isTime(d.modified)) {
    if (counters) counters.malformed++;
    return null;
  }
  if (!advisoryDatabase(id)) {
    if (counters) counters.prefixes.set(advisoryPrefix(id), (counters.prefixes.get(advisoryPrefix(id)) ?? 0) + 1);
    return null;
  }
  if (d.withdrawn !== undefined && d.withdrawn !== null) return null;
  const aliases = Array.isArray(d.aliases) ? d.aliases : [];
  const cves = [...new Set([id, ...aliases].filter((a): a is string => typeof a === 'string' && CVE_ID_RE.test(a)))];
  if (cves.length === 0) return null;

  const byName = new Map<string, { ranges: string[][]; versions: Set<string> }>();
  for (const a of Array.isArray(d.affected) ? d.affected : []) {
    const aff = asRecord(a);
    const pkg = asRecord(aff?.package);
    if (!aff || !pkg || typeof pkg.ecosystem !== 'string' || pkg.ecosystem.split(':')[0] !== eco || !isPackageName(pkg.name)) continue;
    let entry = byName.get(pkg.name);
    if (!entry) byName.set(pkg.name, (entry = { ranges: [], versions: new Set() }));
    for (const r of Array.isArray(aff.ranges) ? aff.ranges : []) {
      const events = compactRange(r);
      if (events && !entry.ranges.some((x) => x.join('\n') === events.join('\n'))) entry.ranges.push(events);
    }
    for (const v of Array.isArray(aff.versions) ? aff.versions : []) if (isVersionText(v)) entry.versions.add(v);
  }
  const affected: OsvAffected[] = [];
  for (const [name, { ranges: all, versions }] of byName) {
    let ranges = all;
    if (ranges.length > OSV.maxRanges) ranges = [...ranges.slice(0, OSV.maxRanges - 1), ['?ranges=capped']];
    let extra = extraVersions(eco, [...versions], ranges);
    if (extra.length > OSV.maxExtraVersions) {
      extra = extra.slice(0, OSV.maxExtraVersions);
      ranges = [...ranges, ['?versions=capped']];
    }
    // Only GIT ranges, or nothing: "version not checked", never "not affected".
    if (ranges.length === 0 && extra.length === 0) ranges = [['?git=unknown']];
    affected.push(extra.length > 0 ? [name, ranges, extra] : [name, ranges]);
  }
  if (affected.length === 0) return null;
  return [id, d.modified as string, cves, affected];
}

/** Shape and field checks for a record read back from the cache (the same rules as compactRecord). */
export function isValidLite(rec: unknown): rec is OsvLite {
  if (!Array.isArray(rec) || rec.length !== 4) return false;
  const [id, modified, cves, affected] = rec as unknown[];
  if (typeof id !== 'string' || !ADVISORY_ID_RE.test(id) || !advisoryDatabase(id) || !isTime(modified)) return false;
  if (!Array.isArray(cves) || cves.length === 0 || !cves.every((c) => typeof c === 'string' && CVE_ID_RE.test(c))) return false;
  if (!Array.isArray(affected) || affected.length === 0) return false;
  return affected.every((a) => {
    if (!Array.isArray(a) || a.length < 2 || a.length > 3 || !isPackageName(a[0])) return false;
    const [, ranges, extra] = a as unknown[];
    if (!Array.isArray(ranges) || ranges.length > OSV.maxRanges + 1) return false;
    if (!ranges.every((r) => Array.isArray(r) && r.length > 0 && r.length <= OSV.maxEvents && r.every((e) => typeof e === 'string' && EVENT_RE.test(e)))) return false;
    if (extra === undefined) return ranges.length > 0;
    return Array.isArray(extra) && extra.length > 0 && extra.length <= OSV.maxExtraVersions && extra.every(isVersionText);
  });
}

const byRecordId = (a: OsvLite, b: OsvLite) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);

// ── Mirror file ──

export function mirrorPath(cacheDir: string): string {
  return path.join(cacheDir, 'sources', OSV.mirrorFile);
}

/** Read the cached mirror; a missing, unreadable or unknown-version file is an empty mirror. */
export async function readMirror(file: string, log: Logger): Promise<OsvMirror> {
  let raw: unknown;
  try {
    raw = JSON.parse(gunzipSync(await readFile(file), { maxOutputLength: 256 * 1024 * 1024 }).toString('utf8'));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') log.warn(`osv: cached mirror unreadable (${describe(err)}); starting over`);
    return { version: 1, ecosystems: {} };
  }
  const o = asRecord(raw);
  const ecosystems = asRecord(o?.ecosystems);
  if (!o || o.version !== 1 || !ecosystems) {
    log.warn('osv: cached mirror has an unknown format; starting over');
    return { version: 1, ecosystems: {} };
  }
  const mirror: OsvMirror = { version: 1, ecosystems: {} };
  const missing = asRecord(o.missing);
  for (const eco of PACKAGE_ECOSYSTEMS) {
    const since = missing && Object.hasOwn(missing, eco) ? missing[eco] : null;
    if (isTime(since)) (mirror.missing ??= {})[eco] = since;
    const c = Object.hasOwn(ecosystems, eco) ? asRecord(ecosystems[eco]) : null;
    if (!c || !isTime(c.full_sync_at) || !isTime(c.fetched_at) || !Array.isArray(c.records)) continue;
    const records = c.records.filter(isValidLite);
    const dropped = c.records.length - records.length;
    if (dropped > 0) log.warn(`osv: ${eco}: dropped ${dropped} invalid records from the cached mirror`);
    const copy: OsvCopy = {
      full_sync_at: c.full_sync_at,
      zip_etag: typeof c.zip_etag === 'string' && c.zip_etag.length <= 200 ? c.zip_etag : null,
      cursor: isTime(c.cursor) ? c.cursor : null,
      fetched_at: c.fetched_at,
      records: records.sort(byRecordId),
    };
    if (isTime(c.full_failed_at)) {
      copy.full_failed_at = c.full_failed_at;
      copy.full_error = typeof c.full_error === 'string' ? c.full_error.slice(0, 300) : 'unknown error';
    }
    mirror.ecosystems[eco] = copy;
  }
  return mirror;
}

async function writeMirror(file: string, mirror: OsvMirror): Promise<number> {
  const body = gzipSync(JSON.stringify(mirror));
  await mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  await writeFile(tmp, body);
  await rename(tmp, file);
  return body.length;
}

// ── Sync ──

interface Env {
  http: HttpClient;
  cfg: Config;
  limits: SanityLimits;
  log: Logger;
  signal: AbortSignal;
  clock: () => number;
  tmpDir: string;
  counters: Counters;
  /** Shared limit on record downloads in flight. */
  slots: Semaphore;
}

class Semaphore {
  private waiting: (() => void)[] = [];
  private free: number;
  constructor(size: number) {
    this.free = size;
  }
  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.free > 0) this.free--;
    else await new Promise<void>((resolve) => this.waiting.push(resolve));
    try {
      return await fn();
    } finally {
      const next = this.waiting.shift();
      if (next) next();
      else this.free++;
    }
  }
}

const yieldToLoop = () => new Promise<void>((resolve) => setImmediate(resolve));
const isoNow = (env: Env) => new Date(env.clock()).toISOString();
const hostCheck = (env: Env) => env.cfg.isAllowedHost;

/** Read a dump into a copy; applies the sanity floors. */
async function readDump(eco: PackageEcosystem, file: string, prev: OsvCopy | undefined, etag: string | null, env: Env): Promise<OsvCopy> {
  const zip = new ZipReader(file);
  const records: OsvLite[] = [];
  let newest: string | null = null;
  let newestMs = -Infinity;
  try {
    let n = 0;
    for (const entry of zip.entries) {
      if (entry.name.startsWith('MAL-') || !entry.name.endsWith('.json')) continue;
      // Inflating and parsing ~50,000 records shares the process with the CVE List scan.
      if (++n % 2000 === 0) {
        await yieldToLoop();
        env.signal.throwIfAborted();
      }
      let json: unknown;
      try {
        json = JSON.parse(zip.read(entry).toString('utf8'));
      } catch (err) {
        if (err instanceof SyntaxError) {
          env.counters.malformed++;
          continue;
        }
        throw err;
      }
      const modified = asRecord(json)?.modified;
      if (isTime(modified) && Date.parse(modified) > newestMs) {
        newestMs = Date.parse(modified);
        newest = modified;
      }
      const lite = compactRecord(json, eco, env.counters);
      if (lite) records.push(lite);
    }
  } finally {
    zip.close();
  }
  const floor = env.limits.osvRecords[eco];
  if (records.length < floor) throw new SanityError(`only ${records.length.toLocaleString('en-US')} usable records (expected at least ${floor.toLocaleString('en-US')})`);
  if (prev && records.length < prev.records.length * env.limits.osvMinRatioOfCached) {
    throw new SanityError(`${records.length.toLocaleString('en-US')} usable records, fewer than ${env.limits.osvMinRatioOfCached * 100}% of the cached ${prev.records.length.toLocaleString('en-US')}`);
  }
  const now = isoNow(env);
  return { full_sync_at: now, zip_etag: etag, cursor: newest, fetched_at: now, records: records.sort(byRecordId) };
}

async function fullSync(eco: PackageEcosystem, prev: OsvCopy | undefined, env: Env): Promise<OsvCopy> {
  const { cfg } = env;
  const url = `${cfg.base}/${encodeURIComponent(eco)}/all.zip`;
  const tmp = path.join(env.tmpDir, `osv-${eco}-${process.pid}-${randomBytes(4).toString('hex')}.zip`);
  const t0 = performance.now();
  try {
    const got = await env.http.request(
      url,
      {
        headers: prev?.zip_etag ? { 'if-none-match': prev.zip_etag } : {},
        signal: env.signal,
        timeoutMs: cfg.limits.zipTimeoutMs,
        retryDelaysMs: cfg.limits.zipRetryDelaysMs,
        allowHost: hostCheck(env),
      },
      async (res) => {
        if (res.status === 304) {
          await res.body?.cancel();
          return null;
        }
        const fh = await open(tmp, 'w');
        try {
          const { bytes } = await readCapped(res, cfg.limits.zipBytes, { sink: (chunk) => fh.write(chunk) });
          return { etag: res.headers.get('etag'), bytes };
        } finally {
          await fh.close();
        }
      },
    );
    if (got === null) {
      if (!prev) throw new Error('all.zip answered 304 without a cached copy');
      env.log.info(`osv: ${eco}: all.zip not modified`);
      const now = isoNow(env);
      const { full_failed_at: _at, full_error: _error, ...rest } = prev;
      return { ...rest, full_sync_at: now, fetched_at: now };
    }
    const t1 = performance.now();
    const copy = await readDump(eco, tmp, prev, got.etag, env);
    env.log.info(
      `osv: ${eco}: full sync, ${formatBytes(got.bytes)} in ${((t1 - t0) / 1000).toFixed(1)} s, ` +
        `${copy.records.length.toLocaleString('en-US')} records in ${((performance.now() - t1) / 1000).toFixed(1)} s`,
    );
    return copy;
  } finally {
    await rm(tmp, { force: true });
  }
}

async function syncFromFile(eco: PackageEcosystem, dir: string, prev: OsvCopy | undefined, env: Env): Promise<OsvCopy> {
  const t0 = performance.now();
  const copy = await readDump(eco, path.join(dir, `${eco}.zip`), prev, null, env);
  env.log.info(`osv: ${eco}: read ${copy.records.length.toLocaleString('en-US')} records from ${dir} (${((performance.now() - t0) / 1000).toFixed(1)} s)`);
  return copy;
}

type Incremental = { kind: 'ok'; copy: OsvCopy; changed: number } | { kind: 'full'; reason: string };

/** Changed IDs since the cursor (minus the overlap), from the head of modified_id.csv. */
async function changedIds(eco: PackageEcosystem, cursor: string, env: Env): Promise<{ ids: string[]; newest: string | null } | { full: string }> {
  const { cfg } = env;
  const url = `${cfg.base}/${encodeURIComponent(eco)}/modified_id.csv`;
  const stopBefore = Date.parse(cursor) - cfg.csvOverlapMs;
  const ids = new Set<string>();
  let newest: string | null = null;
  let newestMs = -Infinity;
  let offset = 0;
  let chunk = cfg.csvHeadBytes;
  let carry = '';
  let badIds = 0;
  for (;;) {
    const want = Math.min(chunk, cfg.csvMaxBytes - offset);
    const part = await env.http.request(
      url,
      { headers: { range: `bytes=${offset}-${offset + want - 1}` }, signal: env.signal, accept: [416], allowHost: hostCheck(env) },
      async (res) => {
        if (res.status === 416) {
          await res.body?.cancel();
          return { text: '', complete: true, fromStart: false, bytes: 0 };
        }
        if (res.status === 206) {
          const { body, bytes } = await readCapped(res, want);
          const m = /^bytes (\d+)-(\d+)\/(\d+|\*)$/.exec(res.headers.get('content-range') ?? '');
          const complete = m ? m[3] !== '*' && Number(m[2]) + 1 >= Number(m[3]) : bytes < want;
          if (m && Number(m[1]) !== offset) throw new FetchRejected(`asked for bytes from ${offset}, got ${m[0]}`);
          return { text: body.toString('utf8'), complete, fromStart: false, bytes };
        }
        // 200: the server ignored Range and sends the whole file; read it up to the cap.
        const { body, bytes, truncated } = await readCapped(res, cfg.csvMaxBytes, { truncate: true });
        return { text: body.toString('utf8'), complete: !truncated, fromStart: true, bytes };
      },
    );
    if (part.fromStart) {
      carry = '';
      offset = 0;
    }
    const lines = (carry + part.text).split('\n');
    carry = part.complete ? '' : (lines.pop() ?? '');
    for (const raw of lines) {
      const line = raw.trim();
      if (line === '') continue;
      const comma = line.indexOf(',');
      const time = comma > 0 ? line.slice(0, comma) : '';
      const t = Date.parse(time);
      if (Number.isNaN(t)) return { full: `unreadable line in modified_id.csv: "${line.slice(0, 60)}"` };
      if (t < stopBefore) return { ids: [...ids], newest };
      if (t > newestMs) {
        newestMs = t;
        newest = time;
      }
      const id = line.slice(comma + 1);
      if (id.startsWith('MAL-')) continue;
      if (!ADVISORY_ID_RE.test(id)) {
        badIds++;
        if (badIds === 1) env.log.warn(`osv: ${eco}: modified_id.csv lists an invalid ID; skipped`);
        continue;
      }
      if (!advisoryDatabase(id)) {
        env.counters.prefixes.set(advisoryPrefix(id), (env.counters.prefixes.get(advisoryPrefix(id)) ?? 0) + 1);
        continue;
      }
      ids.add(id);
      if (ids.size > cfg.maxChangedIds) return { full: `more than ${cfg.maxChangedIds.toLocaleString('en-US')} changed records` };
    }
    if (part.complete) return { ids: [...ids], newest };
    offset += part.bytes;
    chunk *= 2;
    if (offset >= cfg.csvMaxBytes || part.bytes === 0) return { full: `the cursor is more than ${formatBytes(cfg.csvMaxBytes)} into modified_id.csv` };
  }
}

async function incremental(eco: PackageEcosystem, prev: OsvCopy, env: Env): Promise<Incremental> {
  if (!prev.cursor) return { kind: 'full', reason: 'the copy has no cursor' };
  const changes = await changedIds(eco, prev.cursor, env);
  if ('full' in changes) return { kind: 'full', reason: changes.full };
  const { cfg } = env;
  type Fetched = { id: string; json: unknown } | { id: string; gone: true };
  const settled = await Promise.allSettled(
    changes.ids.map((id) =>
      env.slots.run(() =>
        env.http.request(
          `${cfg.base}/${encodeURIComponent(eco)}/${encodeURIComponent(id)}.json`,
          { signal: env.signal, accept: [404], allowHost: hostCheck(env) },
          async (res): Promise<Fetched> => {
            if (res.status === 404) {
              await res.body?.cancel();
              return { id, gone: true };
            }
            const { body } = await readCapped(res, cfg.limits.recordBytes);
            try {
              return { id, json: JSON.parse(body.toString('utf8')) };
            } catch {
              throw new FetchRejected(`${id}.json is not JSON`);
            }
          },
        ),
      ),
    ),
  );
  const failed = settled.find((s): s is PromiseRejectedResult => s.status === 'rejected');
  if (failed) throw failed.reason;
  const fetched = settled.map((s) => (s as PromiseFulfilledResult<Fetched>).value);
  const gone = fetched.filter((f) => 'gone' in f).length;
  if (gone >= cfg.max404) throw new Error(`${gone} changed records answered 404, which looks like an upstream fault; nothing removed`);

  const byId = new Map(prev.records.map((r) => [r[0], r]));
  for (const f of fetched) {
    if ('gone' in f) {
      byId.delete(f.id);
      continue;
    }
    const got = asRecord(f.json)?.id;
    if (got !== f.id) {
      env.log.warn(`osv: ${eco}: ${f.id}.json holds the record ${typeof got === 'string' ? got.slice(0, 40) : 'without an id'}; dropped`);
      continue;
    }
    const lite = compactRecord(f.json, eco, env.counters);
    if (lite) byId.set(f.id, lite);
    else byId.delete(f.id);
  }
  const cursor = changes.newest !== null && Date.parse(changes.newest) > Date.parse(prev.cursor) ? changes.newest : prev.cursor;
  return { kind: 'ok', copy: { ...prev, cursor, fetched_at: isoNow(env), records: [...byId.values()].sort(byRecordId) }, changed: fetched.length };
}

interface EcoResult {
  copy: OsvCopy | undefined;
  stale: boolean;
  error: string | null;
}

async function syncEcosystem(eco: PackageEcosystem, prev: OsvCopy | undefined, deps: OsvDeps, env: Env): Promise<EcoResult> {
  /** Why this run's full sync failed, when it did. */
  let rejected: string | null = null;
  const failed = (copy: OsvCopy, why: string): OsvCopy => ({ ...copy, full_failed_at: isoNow(env), full_error: why.slice(0, 300) });
  try {
    if (deps.osvDir) return { copy: await syncFromFile(eco, deps.osvDir, prev, env), stale: false, error: null };
    if (deps.offline) return { copy: prev, stale: true, error: prev ? null : 'offline; no cached copy' };
    const now = env.clock();
    const age = prev ? now - Date.parse(prev.full_sync_at) : Infinity;
    const due = !(age >= 0 && age < env.cfg.fullSyncMs);
    // A full dump that failed less than a day ago is not downloaded again yet.
    const sinceFailed = prev?.full_failed_at ? now - Date.parse(prev.full_failed_at) : Infinity;
    const waiting = sinceFailed >= 0 && sinceFailed < env.cfg.fullRetryMs;
    if (prev && (!due || waiting)) {
      const t0 = performance.now();
      const inc = await incremental(eco, prev, env);
      if (inc.kind === 'ok') {
        env.log.info(`osv: ${eco}: ${inc.changed} changed records applied (${((performance.now() - t0) / 1000).toFixed(1)} s)`);
        return { copy: inc.copy, stale: false, error: null };
      }
      if (waiting) throw new Error(`${inc.reason}; the full dump failed (${prev.full_error}) and is retried after ${new Date(Date.parse(prev.full_failed_at!) + env.cfg.fullRetryMs).toISOString()}`);
      env.log.info(`osv: ${eco}: ${inc.reason}; reading the full dump`);
    }
    try {
      return { copy: await fullSync(eco, prev, env), stale: false, error: null };
    } catch (err) {
      if (!prev || env.signal.aborted) throw err;
      rejected = describe(err);
    }
    // Keep the copy current from modified_id.csv until the dump is retried (unless that was just tried).
    env.log.warn(`osv: ${eco}: full dump failed (${rejected}); retried in ${env.cfg.fullRetryMs / 3_600_000} h, incremental updates meanwhile`);
    const inc = due ? await incremental(eco, prev, env) : null;
    if (inc?.kind === 'ok') {
      env.log.info(`osv: ${eco}: ${inc.changed} changed records applied to the cached copy`);
      return { copy: failed(inc.copy, rejected), stale: false, error: null };
    }
    return { copy: failed(prev, rejected), stale: true, error: inc ? `${rejected}; ${inc.reason}` : rejected };
  } catch (err) {
    const message = env.signal.aborted && !deps.signal?.aborted ? `the OSV step ran out of time (${env.cfg.budgetMs / 1000} s)` : describe(err);
    env.log.warn(`osv: ${eco}: ${message}${prev ? '; using the cached copy' : '; no cached copy'}`);
    return { copy: prev && rejected ? failed(prev, rejected) : prev, stale: true, error: rejected ? `${rejected}; ${message}` : message };
  }
}

/** Load and update the mirror; never throws. Each ecosystem fails on its own. */
export async function loadOsv(deps: OsvDeps): Promise<{ data: OsvData; status: SourceStatus }> {
  const cfg: Config = { ...OSV, ...deps.config };
  const clock = deps.clock ?? Date.now;
  const budget = AbortSignal.timeout(cfg.budgetMs);
  const env: Env = {
    http: deps.http,
    cfg,
    limits: deps.limits,
    log: deps.log,
    signal: deps.signal ? AbortSignal.any([deps.signal, budget]) : budget,
    clock,
    tmpDir: deps.tmpDir ?? os.tmpdir(),
    counters: { prefixes: new Map(), malformed: 0 },
    slots: new Semaphore(cfg.concurrency),
  };
  const file = mirrorPath(deps.cacheDir);
  const t0 = performance.now();
  const prev = await readMirror(file, deps.log);
  const results = await Promise.all(PACKAGE_ECOSYSTEMS.map((eco) => syncEcosystem(eco, prev.ecosystems[eco], deps, env)));

  const mirror: OsvMirror = { version: 1, ecosystems: {} };
  const statuses = {} as Record<PackageEcosystem, OsvEcosystemStatus>;
  let missingChanged = false;
  PACKAGE_ECOSYSTEMS.forEach((eco, i) => {
    const { copy, stale, error } = results[i];
    const since = copy ? null : (prev.missing?.[eco] ?? new Date(clock()).toISOString());
    if (copy) mirror.ecosystems[eco] = copy;
    else (mirror.missing ??= {})[eco] = since!;
    if (since !== (prev.missing?.[eco] ?? null)) missingChanged = true;
    statuses[eco] = { ok: copy !== undefined, stale, fetched_at: copy?.fetched_at ?? null, modified: copy?.cursor ?? null, advisories: copy?.records.length ?? 0, error, ...(since ? { missing_since: since } : {}) };
  });
  for (const [prefix, n] of env.counters.prefixes) deps.log.warn(`osv: skipped ${n} records with the prefix ${prefix}, which has no licence notice in ATTRIBUTION`);
  if (env.counters.malformed > 0) deps.log.warn(`osv: skipped ${env.counters.malformed} malformed records`);

  // Also written when only a failure time changed, so the next run waits instead of downloading again.
  const failureChanged = PACKAGE_ECOSYSTEMS.some((eco, i) => results[i].copy?.full_failed_at !== prev.ecosystems[eco]?.full_failed_at);
  if (!deps.offline && (missingChanged || failureChanged || results.some((r) => !r.stale))) {
    try {
      const bytes = await writeMirror(file, mirror);
      deps.log.info(`osv: mirror ${formatBytes(bytes)} gzip written (${((performance.now() - t0) / 1000).toFixed(1)} s for the OSV step)`);
    } catch (err) {
      deps.log.warn(`osv: could not write the mirror (${describe(err)})`);
    }
  }
  return { data: { mirror, statuses }, status: osvStatus(statuses, cfg) };
}

/**
 * The one `osv` entry of meta.sources. `ok` when any ecosystem has a copy (the watchdog fails a run
 * at once only when nothing is usable); `stale` when any ecosystem is stale or missing, with the
 * oldest copy's time or the time since when an ecosystem has had no copy, whichever is older, so a
 * copy stale for 48 hours, or an ecosystem missing for 48 hours, fails the watchdog like any other
 * source.
 */
export function osvStatus(statuses: Record<PackageEcosystem, OsvEcosystemStatus>, cfg: Pick<Config, 'info' | 'base'> = OSV): SourceStatus {
  const list = PACKAGE_ECOSYSTEMS.map((eco) => ({ eco, ...statuses[eco] }));
  const withCopy = list.filter((s) => s.ok);
  const times = list.map((s) => (s.ok ? s.fetched_at : s.missing_since)).filter((t): t is string => typeof t === 'string');
  const oldest = withCopy.length > 0 ? (times.sort((a, b) => Date.parse(a) - Date.parse(b))[0] ?? null) : null;
  const newest = withCopy.map((s) => s.modified).filter((t): t is string => t !== null).sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
  const problems = list.filter((s) => s.stale || !s.ok).map((s) => `${s.eco}: ${s.error ?? (s.ok ? 'cached copy' : 'no copy')}`);
  return {
    id: cfg.info.id,
    name: cfg.info.name,
    url: cfg.base,
    ok: withCopy.length > 0,
    stale: problems.length > 0,
    fetched_at: oldest,
    upstream_version: newest,
    records: withCopy.reduce((a, s) => a + s.advisories, 0),
    error: problems.length > 0 ? problems.join('; ').slice(0, 500) : null,
    license: cfg.info.license,
  };
}
