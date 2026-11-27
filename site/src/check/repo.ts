/**
 * Check a public GitHub repository without an SBOM: list its files with GitHub's API, pick the
 * lockfiles and SBOMs the parser knows (files.ts), and download them from raw.githubusercontent.com.
 * Nothing goes to CVErdict: the repository name goes to GitHub, and the files are matched in the
 * browser like a dropped file.
 *
 * - One API call for the default branch (skipped when a branch is given), one for the whole tree.
 *   Without the API (its limit for visitors is 60 requests an hour), the files at the root are tried
 *   by name on raw.githubusercontent.com instead, and the result says so.
 * - At most MAX_REPO_FILES files and MAX_REPO_BYTES in all; folders in SKIP_DIRS are never read, and
 *   a go.sum next to a go.mod is left out, as on the command line.
 * - Names from the user and from GitHub are checked and URL-encoded segment by segment.
 */
import { SKIP_DIRS, isCheckable } from './files';

export const MAX_REPO_FILES = 50;
export const MAX_REPO_BYTES = 100 * 1024 * 1024;
export const API = 'https://api.github.com';
export const RAW = 'https://raw.githubusercontent.com';

/** Lockfiles and SBOMs tried at the root when the API cannot list the tree. */
export const ROOT_NAMES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'poetry.lock',
  'uv.lock',
  'Pipfile.lock',
  'requirements.txt',
  'go.mod',
  'Cargo.lock',
  'Gemfile.lock',
  'composer.lock',
  'packages.lock.json',
  'gradle.lockfile',
  'bom.json',
  'bom.xml',
];

export interface RepoRef {
  owner: string;
  repo: string;
  /** A branch, tag or commit; null for the default branch. */
  ref: string | null;
}

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;
const REF = /^[A-Za-z0-9._\/-]{1,200}$/;

/**
 * "owner/repo", "github.com/owner/repo", "https://github.com/owner/repo(.git)", or a URL with
 * /tree/<branch>. Null for anything else, a dot-only repository name or a ref with "..".
 */
export function parseRepo(input: string): RepoRef | null {
  let s = input.trim().replace(/^git\+/, '');
  s = s.replace(/^https?:\/\//i, '').replace(/^(?:www\.)?github\.com[/:]/i, '').replace(/^git@github\.com:/i, '');
  s = s.replace(/[?#].*$/, '').replace(/\/+$/, '');
  const parts = s.split('/');
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, '');
  let ref: string | null = null;
  if (parts.length > 2) {
    if (parts[2] !== 'tree' || parts.length < 4) return null;
    ref = parts.slice(3).join('/');
  }
  if (!OWNER.test(owner) || !REPO.test(repo) || /^\.+$/.test(repo)) return null;
  if (ref !== null && (!REF.test(ref) || ref.includes('..'))) return null;
  return { owner, repo, ref };
}

export const repoLabel = (r: RepoRef) => `${r.owner}/${r.repo}${r.ref ? `@${r.ref}` : ''}`;
const enc = (path: string) => path.split('/').map(encodeURIComponent).join('/');
export const rawUrl = (r: RepoRef, ref: string, path: string) => `${RAW}/${encodeURIComponent(r.owner)}/${encodeURIComponent(r.repo)}/${enc(ref)}/${enc(path)}`;

/** Why a repository could not be checked: the page explains each kind. */
export class RepoError extends Error {
  constructor(
    readonly kind: 'invalid' | 'not-found' | 'no-files' | 'network' | 'too-large',
    message: string,
  ) {
    super(message);
    this.name = 'RepoError';
  }
}

export interface TreeEntry {
  path: string;
  type: string;
  size?: number;
}

/**
 * The files to read from a tree listing: lockfile and SBOM names outside SKIP_DIRS, shallowest
 * first, a go.sum left out next to a go.mod, at most `max`. `skipped` counts what the cap cut.
 */
export function pickFiles(entries: readonly TreeEntry[], max = MAX_REPO_FILES): { paths: string[]; skipped: number } {
  const blobs = entries.filter((e) => e.type === 'blob' && typeof e.path === 'string' && e.path.length <= 1024);
  const wanted = blobs.filter((e) => {
    const parts = e.path.split('/');
    return !parts.slice(0, -1).some((d) => SKIP_DIRS.has(d)) && isCheckable(parts[parts.length - 1]);
  });
  const dirOf = (p: string) => p.slice(0, Math.max(0, p.lastIndexOf('/')));
  const goMods = new Set(wanted.filter((e) => e.path.endsWith('go.mod') && e.path.split('/').pop() === 'go.mod').map((e) => dirOf(e.path)));
  const kept = wanted.filter((e) => !(e.path.split('/').pop() === 'go.sum' && goMods.has(dirOf(e.path))));
  kept.sort((a, b) => a.path.split('/').length - b.path.split('/').length || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { paths: kept.slice(0, max).map((e) => e.path), skipped: Math.max(0, kept.length - max) };
}

export interface RepoFiles {
  ref: string;
  files: { path: string; text: string }[];
  /** Files left out by the caps (count), or GitHub's own cut of a very large tree. */
  skipped: number;
  truncated: boolean;
  /** Set when GitHub's API could not be used and only the root was tried. */
  rootOnly: string | null;
}

type Fetch = typeof fetch;

async function getJson(fetchImpl: Fetch, url: string): Promise<{ status: number; body: unknown }> {
  let res: Response;
  try {
    res = await fetchImpl(url, { headers: { accept: 'application/vnd.github+json' } });
  } catch {
    throw new RepoError('network', 'GitHub could not be reached. Check your connection and try again.');
  }
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    // A rate-limit or error page without JSON: the status says enough.
  }
  return { status: res.status, body };
}

/** The repository's lockfiles and SBOMs, downloaded. Throws RepoError. */
export async function fetchRepoFiles(r: RepoRef, fetchImpl: Fetch = fetch): Promise<RepoFiles> {
  const base = `${API}/repos/${encodeURIComponent(r.owner)}/${encodeURIComponent(r.repo)}`;
  let ref = r.ref;
  let paths: string[] | null = null;
  let skipped = 0;
  let truncated = false;
  let rootOnly: string | null = null;
  const limited = (status: number) => status === 403 || status === 429;

  if (ref === null) {
    const info = await getJson(fetchImpl, base);
    if (info.status === 404) throw new RepoError('not-found', `${repoLabel(r)} was not found. It may be private: for a private repository, run the check in CI.`);
    if (info.status === 200) {
      const b = info.body as { default_branch?: unknown; private?: unknown } | null;
      if (typeof b?.default_branch === 'string' && REF.test(b.default_branch)) ref = b.default_branch;
    } else if (!limited(info.status)) throw new RepoError('network', `GitHub answered ${info.status} for ${repoLabel(r)}. Try again in a moment.`);
  }
  if (ref !== null) {
    const tree = await getJson(fetchImpl, `${base}/git/trees/${enc(ref)}?recursive=1`);
    if (tree.status === 404) throw new RepoError('not-found', `${repoLabel({ ...r, ref })} was not found. Check the branch name, or run the check in CI for a private repository.`);
    if (tree.status === 200) {
      const b = tree.body as { tree?: unknown; truncated?: unknown } | null;
      const picked = pickFiles(Array.isArray(b?.tree) ? (b.tree as TreeEntry[]) : []);
      paths = picked.paths;
      skipped = picked.skipped;
      truncated = b?.truncated === true;
    } else if (!limited(tree.status)) throw new RepoError('network', `GitHub answered ${tree.status} for the files of ${repoLabel(r)}. Try again in a moment.`);
  }
  if (paths === null) {
    // GitHub's API limit for visitors (60 requests an hour) was reached: try the root by name.
    rootOnly = 'GitHub’s API limit for visitors was reached, so only the files at the root of the repository were checked. Try again within the hour for every folder, or run the check in CI.';
    ref ??= 'HEAD';
    paths = ROOT_NAMES;
  }

  const files: { path: string; text: string }[] = [];
  let bytes = 0;
  const queue = [...paths];
  const worker = async () => {
    for (let path = queue.shift(); path !== undefined; path = queue.shift()) {
      let res: Response;
      try {
        res = await fetchImpl(rawUrl(r, ref!, path));
      } catch {
        throw new RepoError('network', `${path} could not be downloaded from GitHub. Try again in a moment.`);
      }
      if (res.status === 404 && rootOnly) continue;
      if (!res.ok) throw new RepoError('network', `GitHub answered ${res.status} for ${path}. Try again in a moment.`);
      const text = await res.text();
      bytes += text.length;
      if (bytes > MAX_REPO_BYTES) throw new RepoError('too-large', `The lockfiles of ${repoLabel(r)} add up to more than ${MAX_REPO_BYTES / 1024 / 1024} MB. Check one of them as a file instead.`);
      files.push({ path, text });
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, queue.length) }, worker));
  if (!files.length) throw new RepoError('no-files', `No lockfile or SBOM was found in ${repoLabel({ ...r, ref: r.ref })}${rootOnly ? ' at its root' : ''}. Commit a lockfile, or check an SBOM as a file.`);
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { ref: ref ?? 'HEAD', files, skipped, truncated, rootOnly };
}
