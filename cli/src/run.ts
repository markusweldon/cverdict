/**
 * One check run, shared by the command line (main.ts) and the GitHub Action (action.ts): find the
 * files, load the index, match, write the reports, and return the exit code.
 *
 * Exit codes: 0 passed, 1 a confirmed CVE at or above --fail-on, 2 the check could not run (bad
 * arguments, no files, no index, or no file could be read).
 */
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { KNOB_DEFAULT } from '../../shared/contract';
import { checkFiles, failing, type FailOn, type Report } from './check';
import { loadPackages } from './data';
import { discover } from './discover';
import { toAnnotations, toJson, toMarkdown, toSarif, toText } from './report';
import { VERSION } from './version';

export const FORMATS = ['text', 'markdown', 'json', 'sarif'] as const;
export type Format = (typeof FORMATS)[number];

export interface Options {
  paths: string[];
  failOn: FailOn;
  knob: number;
  format: Format;
  /** Where the main report goes; null: stdout. */
  output: string | null;
  /** Also write SARIF here. */
  sarif: string | null;
  /** Also append the Markdown report here (a GitHub job summary). */
  summary: string | null;
  /** Print GitHub workflow annotations. */
  annotations: boolean;
  /** packages.json: a URL or a local path; null: the published data. */
  data: string | null;
  cwd: string;
}

export interface Io {
  out: (s: string) => void;
  err: (s: string) => void;
  fetch: typeof fetch;
}

export const DEFAULTS: Omit<Options, 'cwd'> = { paths: ['.'], failOn: 'exploited', knob: KNOB_DEFAULT, format: 'text', output: null, sarif: null, summary: null, annotations: false, data: null };

export interface RunResult {
  code: 0 | 1 | 2;
  report: Report | null;
}

const write = (cwd: string, path: string, text: string) => {
  const p = isAbsolute(path) ? path : join(cwd, path);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
};

export async function run(o: Options, io: Io): Promise<RunResult> {
  const found = discover(o.paths, o.cwd);
  for (const m of found.missing) io.err(`${m}: no such file or directory\n`);
  if (found.truncated) io.err(`Stopped after ${found.files.length} files; name the paths to check to read fewer.\n`);
  if (!found.files.length) {
    io.err(`No lockfile or SBOM found under ${o.paths.join(', ')}. Name one, or see --help for the files read.\n`);
    return { code: 2, report: null };
  }
  let loaded;
  try {
    // A local --data path is relative to the folder checked (the workspace, for the Action).
    loaded = await loadPackages(o.data && !/^https?:\/\//i.test(o.data) ? resolve(o.cwd, o.data) : o.data, io.fetch);
  } catch (e) {
    io.err(`${(e as Error).message}\n`);
    return { code: 2, report: null };
  }
  const report = checkFiles(found.files, o.cwd, loaded.file, o.knob, loaded);
  for (const f of found.skipped) report.notes.push({ file: f, text: 'Left out: go.mod in the same folder lists the versions the build selects.' });
  const main = o.format === 'json' ? toJson(report, o.failOn) : o.format === 'sarif' ? toSarif(report, VERSION) : o.format === 'markdown' ? toMarkdown(report, o.failOn) : toText(report, o.failOn);
  if (o.output) write(o.cwd, o.output, main);
  else io.out(main);
  if (o.sarif) write(o.cwd, o.sarif, toSarif(report, VERSION));
  if (o.summary) {
    const p = isAbsolute(o.summary) ? o.summary : join(o.cwd, o.summary);
    appendFileSync(p, toMarkdown(report, o.failOn));
  }
  if (o.annotations) for (const a of toAnnotations(report)) io.out(`${a}\n`);
  if (report.files.every((f) => f.error)) {
    io.err('No file could be read.\n');
    return { code: 2, report };
  }
  return { code: failing(report, o.failOn).length ? 1 : 0, report };
}
