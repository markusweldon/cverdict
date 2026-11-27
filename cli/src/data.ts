/**
 * Loads v1/packages.json (the tracked CVEs) and v1/packages-older.json (every other CVE an OSV.dev
 * advisory names), the index the Check page uses: from the data branch, then the site's /data/
 * rewrite (MCP_DATA_BASES), or from a URL or local path given with --data. The older file is read
 * from where packages.json came from; without it (older data, or a failed load) the check covers the
 * tracked CVEs only, and says so.
 *
 * Each attempt has a deadline for its headers and a cap on its body; the file is checked for the
 * schema version and the exact row columns before the matcher sees it, so no `__proto__` column
 * reaches rowFromColumns.
 */
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { ROW_COLS, SCHEMA_VERSION, rowsFromTable, type PackagesFile } from '../../shared/contract';
import { mergePackageFiles } from '../../shared/packages';
import { MCP_DATA_BASES } from '../../shared/mcp';

export const PACKAGES_FILE = 'packages.json';
export const OLDER_FILE = 'packages-older.json';
export const TIMEOUT_MS = 20_000;
/** packages.json is under 1 MB today; anything past this is not ours. */
export const MAX_BYTES = 64 * 1024 * 1024;

export class DataError extends Error {
  constructor(
    message: string,
    readonly reasons: readonly string[] = [],
  ) {
    super(message);
    this.name = 'DataError';
  }
}

export interface Loaded {
  /** packages.json, merged with packages-older.json when that loaded. */
  file: PackagesFile;
  /** Where packages.json came from: a URL or a local path. */
  from: string;
  /** CVEs from packages-older.json: no CVE page, so their links go to cve.org. */
  olderIds: ReadonlySet<string>;
  /** Why packages-older.json is not in `file`, or null when it is. */
  olderError: string | null;
}

/** A packages.json that matches the contract well enough to match against; else the reason it does not. */
export function checkPackagesFile(doc: unknown): PackagesFile | string {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return 'not a JSON object';
  const d = doc as Partial<PackagesFile>;
  if (d.schema_version !== SCHEMA_VERSION) return `schema_version ${String(d.schema_version)}, this tool reads ${SCHEMA_VERSION}`;
  if (typeof d.generated_at !== 'string' || Number.isNaN(Date.parse(d.generated_at))) return 'no generated_at';
  if (!Array.isArray(d.sources)) return 'no sources';
  if (!d.cves || !Array.isArray(d.cves.cols) || d.cves.cols.join() !== ROW_COLS.join() || !Array.isArray(d.cves.rows)) return 'cves columns do not match';
  if (typeof d.packages !== 'object' || d.packages === null) return 'no packages';
  return d as PackagesFile;
}

function parseBody(bytes: Uint8Array, where: string): PackagesFile {
  const raw = bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipSync(bytes, { maxOutputLength: MAX_BYTES }) : bytes;
  let doc: unknown;
  try {
    doc = JSON.parse(new TextDecoder().decode(raw));
  } catch (e) {
    throw new DataError(`${where} is not valid JSON: ${(e as Error).message}`);
  }
  const checked = checkPackagesFile(doc);
  if (typeof checked === 'string') throw new DataError(`${where} is not a packages.json this tool can read: ${checked}`);
  return checked;
}

function readLocal(file: string): PackagesFile {
  if (statSync(file).size > MAX_BYTES) throw new DataError(`${file} is larger than ${MAX_BYTES} bytes`);
  return parseBody(readFileSync(file), file);
}

/** The files at a local path: packages.json itself (packages-older.json beside it), or a data directory holding v1/ or the files. */
function loadLocal(path: string): Loaded {
  const candidates = statSync(path).isDirectory() ? [join(path, 'v1', PACKAGES_FILE), join(path, PACKAGES_FILE)] : [path];
  const found = candidates.find((c) => existsSync(c));
  if (!found) throw new DataError(`No ${PACKAGES_FILE} in ${path} (looked for ${candidates.join(' and ')})`);
  const tracked = readLocal(found);
  const olderPath = join(dirname(found), OLDER_FILE);
  if (!existsSync(olderPath)) return withOlder(tracked, found, null, `no ${OLDER_FILE} next to ${found}`);
  try {
    return withOlder(tracked, found, readLocal(olderPath), null);
  } catch (e) {
    return withOlder(tracked, found, null, (e as Error).message);
  }
}

function withOlder(tracked: PackagesFile, from: string, older: PackagesFile | null, olderError: string | null): Loaded {
  const file = mergePackageFiles(tracked, older);
  const trackedIds = new Set(rowsFromTable(tracked.cves).map((r) => r.id));
  const olderIds = new Set(older ? rowsFromTable(older.cves).map((r) => r.id).filter((id) => !trackedIds.has(id)) : []);
  return { file, from, olderIds, olderError };
}

async function fetchCapped(url: string, fetchImpl: typeof fetch, timeoutMs: number): Promise<Uint8Array> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { signal: ctl.signal, redirect: 'follow', headers: { accept: 'application/json' } });
    if (!res.ok) throw new DataError(`HTTP ${res.status}`);
    const len = Number(res.headers.get('content-length'));
    if (len > MAX_BYTES) throw new DataError(`body of ${len} bytes is over the cap`);
    const reader = res.body?.getReader();
    if (!reader) return new Uint8Array(await res.arrayBuffer());
    const chunks: Uint8Array[] = [];
    let n = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > MAX_BYTES) {
        await reader.cancel();
        throw new DataError('body is over the cap');
      }
      chunks.push(value);
    }
    const out = new Uint8Array(n);
    let at = 0;
    for (const c of chunks) {
      out.set(c, at);
      at += c.byteLength;
    }
    return out;
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw new DataError(`no answer in ${timeoutMs / 1000} s`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** A base URL ending in /v1/ for a --data URL: a base given with or without the slash, or packages.json itself. */
export function urlFor(data: string): string {
  if (/\/packages\.json(?:\?.*)?$/.test(data)) return data;
  return `${data.replace(/\/+$/, '')}/${PACKAGES_FILE}`;
}

/** packages.json from `data` (a URL or a local path), else from each default base in turn. */
export async function loadPackages(data: string | null, fetchImpl: typeof fetch = fetch, timeoutMs = TIMEOUT_MS): Promise<Loaded> {
  if (data && !/^https?:\/\//i.test(data)) {
    if (!existsSync(data)) throw new DataError(`--data ${data}: no such file or directory`);
    return loadLocal(data);
  }
  const urls = data ? [urlFor(data)] : MCP_DATA_BASES.map((b) => `${b}${PACKAGES_FILE}`);
  const reasons: string[] = [];
  for (const url of urls) {
    let tracked: PackagesFile;
    try {
      tracked = parseBody(await fetchCapped(url, fetchImpl, timeoutMs), url);
    } catch (e) {
      reasons.push(`${new URL(url).host}: ${(e as Error).message}`);
      continue;
    }
    const olderUrl = url.replace(/packages\.json(\?.*)?$/, OLDER_FILE);
    try {
      return withOlder(tracked, url, parseBody(await fetchCapped(olderUrl, fetchImpl, timeoutMs), olderUrl), null);
    } catch (e) {
      return withOlder(tracked, url, null, `${OLDER_FILE}: ${(e as Error).message}`);
    }
  }
  throw new DataError(`Could not load ${PACKAGES_FILE} (${reasons.join('; ')})`, reasons);
}
