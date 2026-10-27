/**
 * Loads the public data contract (shared/contract.ts) from `${BASE_URL}data/v1/`.
 *
 * Every file is fetched at most once per page load and kept in memory; a failed fetch is evicted
 * so a retry refetches. Row tables are decoded with rowsFromTable; CVE details come from the
 * shard named by shardOf().
 */
import {
  SCHEMA_VERSION,
  rowsFromTable,
  type BatchesFile,
  type ChangesFile,
  type CveDetail,
  type CveShard,
  type KevFile,
  type Meta,
  type Row,
  type RowTable,
  type StatsFile,
} from '../../shared/contract';
import { CVE_ID_RE, shardOf } from '../../shared/shard';

export const DATA_BASE = `${import.meta.env.BASE_URL}data/v1/`;
export const FEEDS_BASE = `${import.meta.env.BASE_URL}data/feeds/`;

export class DataError extends Error {
  constructor(
    message: string,
    readonly url: string,
    readonly status: number | null = null,
  ) {
    super(message);
    this.name = 'DataError';
  }
}

/** A cached remote value: `peek()` is synchronous once `load()` has resolved. */
export interface Loader<T> {
  readonly key: string;
  load(): Promise<T>;
  peek(): T | undefined;
}

export interface DataClient {
  readonly base: string;
  readonly meta: Loader<Meta>;
  /** Rows with score ≥ SIGNAL_MIN_SCORE or exploited/weaponized (enough for any knob ≥ 35). */
  readonly signal: Loader<Row[]>;
  /** Every CVE in the window (~700 KB gzip): loaded lazily. */
  readonly index: Loader<Row[]>;
  readonly stats: Loader<StatsFile>;
  readonly batches: Loader<BatchesFile>;
  readonly kev: Loader<KevFile>;
  readonly changes: Loader<ChangesFile>;
  /** The CVE's full record, or null when it is not in our data (outside the window and not in KEV). */
  detail(id: string): Loader<CveDetail | null>;
  /** generated_at of the newest meta.json, bypassing every cache (null when unreachable). */
  latestGeneratedAt(): Promise<string | null>;
  url(path: string): string;
}

export function normalizeCveId(id: string): string | null {
  const n = id.trim().toUpperCase();
  return CVE_ID_RE.test(n) ? n : null;
}

export function createDataClient(base: string = DATA_BASE, fetchImpl: typeof fetch = (input, init) => fetch(input, init)): DataClient {
  const pending = new Map<string, Promise<unknown>>();
  const resolved = new Map<string, unknown>();

  async function getJson(path: string, init?: RequestInit): Promise<unknown> {
    const url = base + path;
    let res: Response;
    try {
      res = await fetchImpl(url, init);
    } catch {
      throw new DataError(`Network error while loading ${path}`, url);
    }
    if (!res.ok) throw new DataError(`${path} returned HTTP ${res.status}`, url, res.status);
    let json: unknown;
    try {
      json = await res.json();
    } catch {
      throw new DataError(`${path} is not valid JSON`, url, res.status);
    }
    const version = (json as { schema_version?: unknown } | null)?.schema_version;
    if (version !== SCHEMA_VERSION) {
      throw new DataError(`${path} uses schema version ${String(version)}; this site reads version ${SCHEMA_VERSION}`, url, res.status);
    }
    return json;
  }

  function resource<T>(path: string, parse: (json: unknown) => T): Loader<T> {
    return {
      key: path,
      peek: () => resolved.get(path) as T | undefined,
      load() {
        let p = pending.get(path) as Promise<T> | undefined;
        if (!p) {
          p = getJson(path).then(parse);
          pending.set(path, p);
          p.then(
            (value) => resolved.set(path, value),
            () => pending.delete(path),
          );
        }
        return p;
      },
    };
  }

  const json = <T>(value: unknown) => value as T;
  const table = (value: unknown) => rowsFromTable(value as RowTable);
  const shards = new Map<string, Loader<CveShard>>();
  const shard = (name: string): Loader<CveShard> => {
    let l = shards.get(name);
    if (!l) shards.set(name, (l = resource<CveShard>(`cve/${name}.json`, json)));
    return l;
  };

  return {
    base,
    meta: resource<Meta>('meta.json', json),
    signal: resource('signal.json', table),
    index: resource('index.json', table),
    stats: resource<StatsFile>('stats.json', json),
    batches: resource<BatchesFile>('batches.json', json),
    kev: resource<KevFile>('kev.json', json),
    changes: resource<ChangesFile>('changes.json', json),
    detail(id) {
      const norm = normalizeCveId(id);
      if (!norm) return { key: `cve:?${id}`, peek: () => null, load: () => Promise.resolve(null) };
      const s = shard(shardOf(norm));
      const pick = (items: CveShard['items']) => (Object.prototype.hasOwnProperty.call(items, norm) ? items[norm] : null);
      return {
        key: `cve:${norm}`,
        peek: () => {
          const v = s.peek();
          return v ? pick(v.items) : undefined;
        },
        load: async () => pick((await s.load()).items),
      };
    },
    async latestGeneratedAt() {
      try {
        return ((await getJson('meta.json', { cache: 'no-store' })) as Meta).generated_at;
      } catch {
        return null;
      }
    },
    url: (path) => base + path,
  };
}

export const data: DataClient = createDataClient();
