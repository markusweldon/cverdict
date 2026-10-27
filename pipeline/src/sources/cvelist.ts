/**
 * CVE List V5: one streaming pass over every record. `git ls-tree -r -z <rev> cves/` feeds blob
 * SHAs to a single `git cat-file --batch`, so it works on a --no-checkout clone and holds at most
 * one raw record (plus pipe buffers) in memory.
 */
import path from 'node:path';
import type { SourceStatus } from '../../../shared/contract';
import { CISA_ADP, CVELIST, GIT_TIMEOUT_MS, type SanityLimits } from '../config';
import { cisaAdpFlags, normalizeCve, readCveMeta, recordAiCredit } from '../normalize';
import type { History, Logger, NormalizedCve, RunContext } from '../types';
import { monthKey } from '../util/dates';
import { catFileBatch, commitDate, existingRepoHead, GitError, lsTree, syncShallowClone } from '../util/git';
import { since } from '../util/log';
import { requireAtLeast, statusFromGit, type GitRevision } from './source';

/** `cves/<year>/<n>xxx/CVE-<year>-<seq>.json`; sequence numbers have 4 to 7+ digits. */
const RECORD_PATH_RE = /^cves\/\d{4}\/\d+xxx\/CVE-\d{4}-\d{4,}\.json$/;
const PROGRESS_EVERY = 100_000;

export interface CvelistRepo extends GitRevision {
  dir: string;
}

async function countRecordFiles(dir: string, commit: string, signal?: AbortSignal): Promise<number> {
  let count = 0;
  for await (const entry of lsTree(dir, commit, ['cves/'], signal)) {
    if (entry.type === 'blob' && RECORD_PATH_RE.test(entry.path)) count++;
  }
  return count;
}

/**
 * Resolve the revision to read: HEAD of an existing `--cvelist-dir` (never modified), or the
 * cache clone `<cache>/git/cvelistV5`, cloned or fetched first unless offline. A fetched commit
 * is adopted only if it has enough record files. Throws when no usable revision exists (fatal).
 */
export async function openCvelist(
  ctx: RunContext,
  cvelistDir: string | undefined,
  limits: SanityLimits,
  signal?: AbortSignal,
): Promise<CvelistRepo> {
  const clone = cvelistDir
    ? { dir: cvelistDir, commit: await existingRepoHead(cvelistDir, signal), stale: false, error: null }
    : await syncShallowClone({
        remote: CVELIST.remote,
        branch: CVELIST.branch,
        dir: path.join(ctx.cacheDir, 'git', CVELIST.cloneDir),
        offline: ctx.offline,
        log: ctx.log,
        timeoutMs: GIT_TIMEOUT_MS,
        signal,
        accept: async (dir, commit) => {
          const files = await countRecordFiles(dir, commit, signal);
          return files >= limits.cvelistRecords ? null : `only ${files} record files`;
        },
      });
  return { ...clone, committedAt: await commitDate(clone.dir, clone.commit, signal) };
}

/** cvelistV5 layout: CVE-2026-104596 → cves/2026/104xxx/CVE-2026-104596.json. */
export function recordPath(id: string): string {
  const [, year, seq] = id.split('-');
  return `cves/${year}/${seq.slice(0, -3) || '0'}xxx/${id}.json`;
}

interface BlobRequest {
  /** Object name for cat-file: a blob SHA, or `<commit>:<path>` for a by-path lookup. */
  name: string;
  path: string;
  /** A by-path lookup issued after the tree listing (not part of the counted pass). */
  lookup: boolean;
}

/**
 * Raw record blobs in tree order through one cat-file process, followed by by-path lookups of
 * `extraIds()` (awaited only once the tree listing is exhausted). Missing lookups are skipped.
 */
async function* recordBlobs(
  repo: CvelistRepo,
  extraIds: () => Promise<Iterable<string>>,
  signal?: AbortSignal,
): AsyncGenerator<{ path: string; data: Buffer; lookup: boolean }> {
  async function* requests(): AsyncGenerator<BlobRequest> {
    for await (const entry of lsTree(repo.dir, repo.commit, ['cves/'], signal)) {
      if (entry.type === 'blob' && RECORD_PATH_RE.test(entry.path)) yield { name: entry.sha, path: entry.path, lookup: false };
    }
    for (const id of await extraIds()) {
      const file = recordPath(id);
      yield { name: `${repo.commit}:${file}`, path: file, lookup: true };
    }
  }
  for await (const { item, data } of catFileBatch(repo.dir, requests(), (r) => r.name, signal)) {
    if (data) yield { path: item.path, data, lookup: item.lookup };
    else if (!item.lookup) throw new GitError(`missing blob ${item.name} for ${item.path}`);
  }
}

export interface ScanOptions {
  windowStart: Date;
  now: Date;
  /**
   * CVE IDs in the KEV catalog (kept even outside the window). The pass does not wait for it:
   * KEV records it could not recognise in time are looked up by path after the tree listing.
   */
  kevIds: Promise<ReadonlySet<string>>;
  minRecords: number;
  log: Logger;
  signal?: AbortSignal;
}

export interface CvelistScan {
  /** PUBLISHED records in the window, plus KEV-listed ones (catalog or CISA-ADP KEV block). */
  cves: NormalizedCve[];
  history: History;
  rejectedInWindow: number;
  /** Records carrying a CISA-ADP container. */
  adpRecords: number;
  /** Blobs that were not parseable CVE records. */
  invalid: number;
  windowPublished: number;
  /** PUBLISHED after `now` (only possible with a frozen --now); never in the window. */
  future: number;
  /** KEV records added by the by-path lookups after the pass. */
  lateKev: number;
}

const bump = (counter: Map<string, number>, key: string) => counter.set(key, (counter.get(key) ?? 0) + 1);

/**
 * Stream every record once: update History counters for all of them and normalise the ones we
 * keep (window ∪ KEV). Throws when fewer than `minRecords` records could be read.
 */
export async function scanCvelist(repo: CvelistRepo, opts: ScanOptions): Promise<CvelistScan> {
  const { windowStart, now, log } = opts;
  const history: History = { published: new Map(), reserved: new Map(), rejected: new Map(), ai: new Map(), totalRecords: 0 };
  const scan: CvelistScan = { cves: [], history, rejectedInWindow: 0, adpRecords: 0, invalid: 0, windowPublished: 0, future: 0, lateKev: 0 };
  const inWindow = (d: Date) => d >= windowStart && d <= now;
  const kept = new Set<string>();
  // Filled in as soon as the catalog arrives; until then only CISA-ADP KEV blocks are recognised.
  const kev: { ids: ReadonlySet<string> | null } = { ids: null };
  const kevReady = opts.kevIds.then((ids) => (kev.ids = ids));
  // After the listing: KEV IDs not kept so far (some may still be in flight; those are skipped below).
  const pendingKev = async () => [...(await kevReady)].filter((id) => !kept.has(id));
  const started = performance.now();

  for await (const { path: file, data, lookup } of recordBlobs(repo, pendingKev, opts.signal)) {
    let record: unknown;
    try {
      record = JSON.parse(data.toString('utf8'));
    } catch {
      if (!lookup) scan.invalid++;
      log.warn(`cvelist: ${file} is not valid JSON`);
      continue;
    }
    const meta = readCveMeta(record);
    if (lookup) {
      // Already counted in the pass; only add a KEV record that the pass did not keep.
      if (meta?.state === 'PUBLISHED' && meta.published && !kept.has(meta.id)) {
        const cve = normalizeCve(record, meta, inWindow(meta.published));
        if (cve) {
          scan.cves.push(cve);
          kept.add(cve.id);
          scan.lateKev++;
        }
      }
      continue;
    }
    if (!meta) {
      scan.invalid++;
      continue;
    }
    history.totalRecords++;
    if (history.totalRecords % PROGRESS_EVERY === 0) log.info(`cvelist: ${history.totalRecords.toLocaleString('en-US')} records (${since(started)})`);
    const adp = cisaAdpFlags(record);
    if (adp.present) scan.adpRecords++;

    if (meta.state === 'PUBLISHED' && meta.published) {
      bump(history.published, monthKey(meta.published));
      if (meta.reserved) bump(history.reserved, monthKey(meta.reserved));
      if (recordAiCredit(record)) bump(history.ai, monthKey(meta.published));
      const windowed = inWindow(meta.published);
      if (windowed) scan.windowPublished++;
      else if (meta.published > now) scan.future++;
      if (windowed || adp.kev || kev.ids?.has(meta.id)) {
        const cve = normalizeCve(record, meta, windowed);
        if (cve) {
          scan.cves.push(cve);
          kept.add(cve.id);
        }
      }
    } else if (meta.state === 'REJECTED') {
      const when = meta.published ?? meta.rejected ?? meta.updated;
      if (when) {
        bump(history.rejected, monthKey(when));
        if (inWindow(when)) scan.rejectedInWindow++;
      }
    }
  }

  requireAtLeast(history.totalRecords, opts.minRecords, 'CVE records');
  log.info(
    `cvelist: ${history.totalRecords.toLocaleString('en-US')} records in ${since(started)} — ` +
      `${scan.windowPublished.toLocaleString('en-US')} published in window, ${scan.cves.length.toLocaleString('en-US')} kept ` +
      `(${scan.lateKev} KEV looked up after the pass), ${scan.rejectedInWindow} rejected in window, ${scan.invalid} invalid` +
      `${scan.future ? `, ${scan.future} published after --now` : ''}`,
  );
  return scan;
}

export function cvelistStatuses(repo: CvelistRepo, scan: CvelistScan): SourceStatus[] {
  return [
    statusFromGit(CVELIST.info, repo, scan.history.totalRecords, null),
    statusFromGit(CISA_ADP.info, repo, scan.adpRecords, scan.adpRecords > 0 ? null : 'no CISA-ADP containers found'),
  ];
}
