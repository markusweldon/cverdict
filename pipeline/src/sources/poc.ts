/**
 * nomi-sec/PoC-in-GitHub: one JSON file per CVE (`YYYY/CVE-….json`), each an array of GitHub
 * repository objects. The tree is listed once; blobs are read (one cat-file process) only for
 * the CVEs we ingested. Forks are dropped.
 */
import path from 'node:path';
import type { SourceStatus } from '../../../shared/contract';
import { GIT_TIMEOUT_MS, POC, type SanityLimits } from '../config';
import type { Logger, PocRepo, RunContext } from '../types';
import { normalizeIso } from '../util/dates';
import { catFileBatch, commitDate, existingRepoHead, lsTree, syncShallowClone } from '../util/git';
import { asArray, asNumber, asObject } from '../util/json';
import { sanitizeUrl } from '../util/text';
import { statusFromGit, type GitRevision, type SourceResult } from './source';

const POC_PATH_RE = /^\d{4}\/(CVE-\d{4}-\d{4,})\.json$/i;
const GITHUB_REPO_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/;

export interface PocTree extends GitRevision {
  dir: string;
  /** CVE ID → blob SHA of its JSON file. */
  files: Map<string, string>;
}

/** List the tree once: CVE ID → blob SHA. */
export async function listPocFiles(dir: string, commit: string, signal?: AbortSignal): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  for await (const entry of lsTree(dir, commit, [], signal)) {
    const match = entry.type === 'blob' ? POC_PATH_RE.exec(entry.path) : null;
    if (match) files.set(match[1].toUpperCase(), entry.sha);
  }
  return files;
}

/** Parse one PoC file: non-fork repos with a GitHub URL and creation date, most-starred first. */
export function parsePocFile(body: Buffer | string): PocRepo[] {
  let doc: unknown;
  try {
    doc = JSON.parse(typeof body === 'string' ? body : body.toString('utf8'));
  } catch {
    return [];
  }
  const repos = new Map<string, PocRepo>();
  for (const item of asArray(doc)) {
    const r = asObject(item);
    if (!r || r.fork === true) continue;
    const url = sanitizeUrl(r.html_url);
    const created = normalizeIso(r.created_at);
    if (!url || !GITHUB_REPO_RE.test(url) || !created || repos.has(url)) continue;
    const stars = asNumber(r.stargazers_count);
    repos.set(url, { url, stars: stars !== null && stars > 0 ? Math.floor(stars) : 0, created, fork: false });
  }
  return [...repos.values()].sort((a, b) => b.stars - a.stars || a.created.localeCompare(b.created));
}

/**
 * Open the PoC repository: an existing `--poc-dir` at HEAD (never modified), or the cache clone
 * under `<cache>/git/poc`, fetched first unless offline. Never throws.
 */
export async function openPoc(
  ctx: RunContext,
  pocDir: string | undefined,
  limits: SanityLimits,
  signal?: AbortSignal,
): Promise<SourceResult<PocTree>> {
  const tooFew = (files: Map<string, string>) =>
    files.size >= limits.pocFiles ? null : `only ${files.size} PoC files (expected at least ${limits.pocFiles})`;
  // Listings made by the sanity check, by commit, so the adopted commit is not listed twice.
  const listings = new Map<string, Map<string, string>>();
  let tree: PocTree;
  try {
    const clone = pocDir
      ? { dir: pocDir, commit: await existingRepoHead(pocDir, signal), stale: false, error: null }
      : await syncShallowClone({
          remote: POC.remote,
          branch: POC.branch,
          dir: path.join(ctx.cacheDir, 'git', POC.cloneDir),
          offline: ctx.offline,
          log: ctx.log,
          timeoutMs: GIT_TIMEOUT_MS,
          signal,
          accept: async (dir, commit) => {
            const files = await listPocFiles(dir, commit, signal);
            listings.set(commit, files);
            return tooFew(files);
          },
        });
    const files = listings.get(clone.commit) ?? (await listPocFiles(clone.dir, clone.commit, signal));
    tree = { ...clone, committedAt: await commitDate(clone.dir, clone.commit, signal), files };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ctx.log.error(`poc-github: unavailable (${message})`);
    return { data: null, status: statusFromGit(POC.info, null, null, message) };
  }
  const problem = tooFew(tree.files);
  if (problem) ctx.log.error(`poc-github: ${problem}`);
  return { data: problem ? null : tree, status: statusFromGit(POC.info, tree, tree.files.size, problem) };
}

/**
 * Read the PoC files of `ids` (those present in the tree) through one cat-file process.
 * Never throws: a read failure leaves no PoC data and is recorded in the returned status.
 */
export async function readPocRepos(
  poc: SourceResult<PocTree>,
  ids: Iterable<string>,
  log: Logger,
  signal?: AbortSignal,
): Promise<{ repos: Map<string, PocRepo[]>; status: SourceStatus }> {
  const repos = new Map<string, PocRepo[]>();
  const tree = poc.data;
  if (!tree) return { repos, status: poc.status };
  const wanted: { id: string; sha: string }[] = [];
  for (const id of ids) {
    const sha = tree.files.get(id);
    if (sha) wanted.push({ id, sha });
  }
  try {
    for await (const { item, data } of catFileBatch(tree.dir, wanted, (w) => w.sha, signal)) {
      const list = data ? parsePocFile(data) : [];
      if (list.length > 0) repos.set(item.id, list);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.error(`poc-github: reading PoC files failed (${message})`);
    return { repos: new Map(), status: { ...poc.status, ok: false, error: message } };
  }
  return { repos, status: poc.status };
}
