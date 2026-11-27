/**
 * Finds the lockfiles and SBOMs to check under the paths given on the command line.
 *
 * A file named on the command line is always read (its format is told by its content if its name
 * says nothing). A directory is walked for the file names the Check page knows, plus common
 * SBOM names, skipping dependency, build and VCS directories. The walk never follows symbolic
 * links, so a link cannot lead it out of the repository or round in a loop.
 */
import { lstatSync, readdirSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { SKIP_DIRS, isCheckable } from '../../site/src/check/files';

export { SKIP_DIRS, isCheckable };

export const MAX_DEPTH = 12;
export const MAX_FILES = 500;

export interface Discovery {
  /** Paths to read, in a stable order (as given, then sorted within each directory walk). */
  files: string[];
  /** go.sum files left out because a go.mod sits next to them (go.mod is exact; go.sum is not). */
  skipped: string[];
  /** Paths that do not exist. */
  missing: string[];
  /** The walk stopped at MAX_FILES. */
  truncated: boolean;
}

/** The files to check under `paths` (relative to `cwd`). */
export function discover(paths: readonly string[], cwd: string, limits = { depth: MAX_DEPTH, files: MAX_FILES }): Discovery {
  const files: string[] = [];
  const seen = new Set<string>();
  const missing: string[] = [];
  let truncated = false;
  const add = (p: string) => {
    if (seen.has(p)) return;
    if (files.length >= limits.files) {
      truncated = true;
      return;
    }
    seen.add(p);
    files.push(p);
  };
  const walk = (dir: string, depth: number) => {
    if (depth > limits.depth || truncated) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (e.isFile() && isCheckable(e.name)) add(join(dir, e.name));
    }
    for (const e of entries) {
      if (e.isDirectory() && !SKIP_DIRS.has(e.name)) walk(join(dir, e.name), depth + 1);
    }
  };
  for (const raw of paths.length ? paths : ['.']) {
    const p = resolve(cwd, raw);
    let st;
    try {
      st = lstatSync(p).isSymbolicLink() ? statSync(p) : lstatSync(p);
    } catch {
      missing.push(raw);
      continue;
    }
    if (st.isDirectory()) walk(p, 0);
    else if (st.isFile()) add(p);
  }
  // go.mod lists the module versions the build selects; go.sum can list versions it does not use.
  const goMods = new Set(files.filter((f) => basename(f) === 'go.mod').map(dirname));
  const skipped = files.filter((f) => basename(f) === 'go.sum' && goMods.has(dirname(f)));
  const kept = files.filter((f) => !skipped.includes(f));
  // Inside cwd: relative, with forward slashes (as annotations and SARIF want). Outside it: absolute.
  const rel = (f: string) => {
    const r = relative(cwd, f);
    return r === '' ? basename(f) : r.startsWith('..') ? f : r.split(sep).join('/');
  };
  return { files: kept.map(rel), skipped: skipped.map(rel), missing, truncated };
}
