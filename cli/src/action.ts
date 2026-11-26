/**
 * The GitHub Action (action/action.yml): reads the inputs GitHub passes as INPUT_* variables, runs
 * the same check as the command line from $GITHUB_WORKSPACE, writes the job summary and
 * annotations, and sets the step outputs. No toolkit dependency: inputs, outputs and the summary
 * are plain environment variables and files.
 */
import { appendFileSync } from 'node:fs';
import { KNOB_DEFAULT } from '../../shared/contract';
import { FAIL_ON, countByGroup, failing, type FailOn } from './check';
import { data as escapeData } from './report';
import { run, type Options } from './run';

export type Env = Readonly<Record<string, string | undefined>>;

/** An input as GitHub names it: INPUT_ and the name in capitals, spaces as underscores, hyphens kept. */
export const input = (env: Env, name: string): string => (env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] ?? '').trim();

const bool = (v: string, fallback: boolean) => (v === '' ? fallback : /^(?:true|yes|1|on)$/i.test(v));

/** Run options from the inputs, or the input that is wrong. */
export function optionsFromInputs(env: Env): Options | string {
  const paths = input(env, 'path')
    .split(/\r?\n/)
    .map((p) => p.trim())
    .filter(Boolean);
  const failOn = (input(env, 'fail-on') || 'exploited').toLowerCase();
  if (!(FAIL_ON as readonly string[]).includes(failOn)) return `fail-on must be one of ${FAIL_ON.join(', ')}`;
  const barText = input(env, 'evidence-bar');
  const knob = barText === '' ? KNOB_DEFAULT : Number(barText);
  if (!Number.isInteger(knob) || knob < 0 || knob > 100) return 'evidence-bar must be a whole number from 0 to 100';
  return {
    paths: paths.length ? paths : ['.'],
    failOn: failOn as FailOn,
    knob,
    format: 'text',
    output: null,
    sarif: input(env, 'sarif-file') || null,
    summary: bool(input(env, 'summary'), true) && env.GITHUB_STEP_SUMMARY ? env.GITHUB_STEP_SUMMARY : null,
    annotations: bool(input(env, 'annotations'), true),
    data: input(env, 'data-url') || null,
    cwd: env.GITHUB_WORKSPACE || process.cwd(),
  };
}

/** Step outputs in the $GITHUB_OUTPUT file format (single-line values only). */
export function outputLines(values: Record<string, string | number | boolean>): string {
  return Object.entries(values)
    .map(([k, v]) => `${k}=${String(v).replace(/[\r\n]/g, ' ')}\n`)
    .join('');
}

export async function runAction(env: Env, io: { out: (s: string) => void; err: (s: string) => void; fetch: typeof fetch }): Promise<number> {
  const o = optionsFromInputs(env);
  if (typeof o === 'string') {
    io.out(`::error title=cverdict-check::${escapeData(o)}\n`);
    return 2;
  }
  const { code, report } = await run(o, {
    ...io,
    err: (s) => io.out(`::error title=cverdict-check::${escapeData(s.trimEnd())}\n`),
  });
  const counts = report ? countByGroup(report.findings) : { exploited: 0, likely: 0, watch: 0, quiet: 0, possible: 0 };
  if (env.GITHUB_OUTPUT) {
    appendFileSync(
      env.GITHUB_OUTPUT,
      outputLines({ ...counts, failed: code !== 0, 'failing-cves': report ? new Set(failing(report, o.failOn).map((f) => f.row.id)).size : 0, 'sarif-file': o.sarif ?? '' }),
    );
  }
  return code;
}
