/** Command-line arguments for `cverdict-check` (node:util parseArgs, no dependency). */
import { parseArgs } from 'node:util';
import { BRAND, REPO_URL } from '../../shared/brand';
import { FAIL_ON, type FailOn } from './check';
import { DEFAULTS, FORMATS, type Format, type Options } from './run';
import { VERSION } from './version';

export const KNOB_MIN = 0;
export const KNOB_MAX = 100;

export const HELP = `${BRAND.slug}-check ${VERSION}: which of your dependencies' CVEs are exploited or likely next

Usage: ${BRAND.slug}-check [paths...] [options]

Paths are lockfiles, SBOMs or folders (default: .). Folders are searched for
package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, poetry.lock,
uv.lock, Pipfile.lock, requirements*.txt, go.mod, go.sum, Cargo.lock,
Gemfile.lock, composer.lock, packages.lock.json, *.lockfile (Gradle), and
CycloneDX or SPDX SBOMs (bom.json, bom.xml, *.cdx.json, *.spdx.json, ...),
skipping node_modules, vendor, build output and VCS folders.

Options:
  --fail-on <tier>     Exit 1 when a confirmed CVE is at this tier or above:
                       exploited (default), likely, watch, quiet, or never
  --evidence-bar <n>   Score a CVE needs for Likely next (default ${DEFAULTS.knob})
  --format <f>         text (default), markdown, json or sarif
  -o, --output <file>  Write the report there instead of stdout
  --sarif <file>       Also write SARIF 2.1.0 (for GitHub code scanning)
  --summary <file>     Also append the Markdown report (e.g. $GITHUB_STEP_SUMMARY)
  --annotations        Print GitHub workflow annotations
  --data <url|path>    packages.json, a data folder or a base URL (default: the
                       published data)
  -h, --help           Show this help
  -v, --version        Show the version

Exit codes: 0 passed, 1 a confirmed CVE at or above --fail-on, 2 could not run.

Files are read locally; only the public index (packages.json) is downloaded.
Checks every CVE an OSV.dev advisory ties to a package version, ranked by
exploitation evidence. Not covered: advisories without a CVE ID, OS packages.
${REPO_URL}/blob/main/cli/README.md
`;

export type Parsed = { kind: 'run'; options: Omit<Options, 'cwd'> } | { kind: 'help' } | { kind: 'version' } | { kind: 'error'; message: string };

export function parseCli(argv: readonly string[]): Parsed {
  let v;
  try {
    v = parseArgs({
      args: [...argv],
      allowPositionals: true,
      strict: true,
      options: {
        'fail-on': { type: 'string' },
        'evidence-bar': { type: 'string' },
        format: { type: 'string' },
        output: { type: 'string', short: 'o' },
        sarif: { type: 'string' },
        summary: { type: 'string' },
        annotations: { type: 'boolean' },
        data: { type: 'string' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
  } catch (e) {
    return { kind: 'error', message: (e as Error).message };
  }
  const a = v.values;
  if (a.help) return { kind: 'help' };
  if (a.version) return { kind: 'version' };
  const failOn = (a['fail-on'] ?? DEFAULTS.failOn).toLowerCase();
  if (!(FAIL_ON as readonly string[]).includes(failOn)) return { kind: 'error', message: `--fail-on must be one of ${FAIL_ON.join(', ')}` };
  const format = (a.format ?? DEFAULTS.format).toLowerCase();
  if (!(FORMATS as readonly string[]).includes(format)) return { kind: 'error', message: `--format must be one of ${FORMATS.join(', ')}` };
  const barText = a['evidence-bar'];
  const knob = barText === undefined ? DEFAULTS.knob : Number(barText);
  if (!Number.isInteger(knob) || knob < KNOB_MIN || knob > KNOB_MAX) return { kind: 'error', message: `--evidence-bar must be a whole number from ${KNOB_MIN} to ${KNOB_MAX}` };
  return {
    kind: 'run',
    options: {
      paths: v.positionals.length ? v.positionals : DEFAULTS.paths,
      failOn: failOn as FailOn,
      knob,
      format: format as Format,
      output: a.output ?? null,
      sarif: a.sarif ?? null,
      summary: a.summary ?? null,
      annotations: a.annotations ?? false,
      data: a.data ?? null,
    },
  };
}
