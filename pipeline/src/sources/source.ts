/** Shared plumbing for source modules: results, status records and sanity errors. */
import type { SourceStatus } from '../../../shared/contract';
import type { SourceInfo } from '../config';
import type { SourceFetch } from '../util/http';

/** Every source returns its data (null when unavailable) plus a status for meta.json. */
export interface SourceResult<T> {
  data: T | null;
  status: SourceStatus;
}

/** Thrown by parsers when a body is well-formed but implausible (truncated, empty, shrunk). */
export class SanityError extends Error {
  override name = 'SanityError';
}

/** Throw a SanityError unless `count >= min`. */
export function requireAtLeast(count: number, min: number, what: string): void {
  if (count < min) {
    throw new SanityError(`only ${count.toLocaleString('en-US')} ${what} (expected at least ${min.toLocaleString('en-US')})`);
  }
}

export function statusFromFetch(info: SourceInfo, fetched: SourceFetch<unknown>): SourceStatus {
  return {
    id: info.id,
    name: info.name,
    url: fetched.url ?? info.home,
    ok: fetched.value !== null,
    stale: fetched.stale,
    fetched_at: fetched.fetchedAt,
    upstream_version: fetched.version,
    records: fetched.records,
    error: fetched.error,
    license: info.license,
  };
}

/** Where a git-backed source's data came from. */
export interface GitRevision {
  commit: string;
  /** Committer date of `commit`: the age of the data, also for an existing local clone. */
  committedAt: string | null;
  stale: boolean;
  error: string | null;
}

export function statusFromGit(info: SourceInfo, rev: GitRevision | null, records: number | null, error: string | null): SourceStatus {
  return {
    id: info.id,
    name: info.name,
    url: info.home,
    ok: rev !== null && error === null,
    stale: rev?.stale ?? true,
    fetched_at: rev?.committedAt ?? null,
    upstream_version: rev?.commit ?? null,
    records,
    error: error ?? rev?.error ?? null,
    license: info.license,
  };
}

/** Group `[key, value]` pairs into a map of arrays, keeping first-seen order. */
export function pushTo<V>(map: Map<string, V[]>, key: string, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}
