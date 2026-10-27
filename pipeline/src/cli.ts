/**
 * Command-line entry point (docs/SPEC.md §2 "CLI"): parse flags, run the pipeline, print a summary.
 * Exit codes: 0 output written and validated, 1 pipeline failure, 2 bad usage.
 */
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { BRAND } from '../../shared/brand';
import { KNOB_MAX, KNOB_MIN, TIERS } from '../../shared/contract';
import { DEFAULT_WINDOW_DAYS } from './config';
import { formatSizeTable } from './validate';
import { ValidationFailedError, run, type RunOptions, type RunSummary } from './run';

const DEFAULT_OUT = 'site/public/data';
const DEFAULT_CACHE = '.cache';

export const USAGE = `Usage: npm run pipeline -- [options]

Builds the ${BRAND.name} data tree (<out>/v1/…, <out>/feeds/…) from public sources.

Options:
  --out <dir>           Output root (default: ${DEFAULT_OUT})
  --previous <dir>      Previous output root, used to compute changes.json
  --cache <dir>         Cache for last-good downloads and git clones (default: ${DEFAULT_CACHE})
  --cvelist-dir <dir>   Use an existing cvelistV5 git clone (never modified)
  --poc-dir <dir>       Use an existing PoC-in-GitHub git clone (never modified)
  --now <iso>           Freeze "now", e.g. 2026-10-26T19:30:00Z (default: current time)
  --window-days <n>     Window size in days (default: ${DEFAULT_WINDOW_DAYS})
  --knob <n>            Default knob for tiers, ${KNOB_MIN}–${KNOB_MAX} (default: 50)
  --offline             Never use the network; read the cache only
  -h, --help            Show this help

Environment:
  SITE_URL              Public site URL used in feed links (default: https://${BRAND.slug}.vercel.app)
`;

export class UsageError extends Error {}

function int(name: string, value: string): number {
  if (!/^\d+$/.test(value)) throw new UsageError(`--${name} must be a whole number, got "${value}"`);
  return Number(value);
}

/** Parse argv into run options; null means --help was requested. */
export function parseCli(argv: string[]): RunOptions | null {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        out: { type: 'string', default: DEFAULT_OUT },
        previous: { type: 'string' },
        cache: { type: 'string', default: DEFAULT_CACHE },
        'cvelist-dir': { type: 'string' },
        'poc-dir': { type: 'string' },
        now: { type: 'string' },
        'window-days': { type: 'string', default: String(DEFAULT_WINDOW_DAYS) },
        knob: { type: 'string' },
        offline: { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    throw new UsageError((e as Error).message);
  }
  if (values.help) return null;

  let now: Date | undefined;
  if (values.now !== undefined) {
    now = new Date(values.now);
    if (Number.isNaN(now.getTime())) throw new UsageError(`--now is not a valid date: "${values.now}"`);
  }
  const windowDays = int('window-days', values['window-days']);
  if (windowDays < 1) throw new UsageError('--window-days must be at least 1');
  const knob = values.knob === undefined ? undefined : int('knob', values.knob);
  if (knob !== undefined && (knob < KNOB_MIN || knob > KNOB_MAX)) throw new UsageError(`--knob must be within ${KNOB_MIN}–${KNOB_MAX}`);

  return {
    out: values.out,
    previous: values.previous ?? null,
    cache: values.cache,
    cvelistDir: values['cvelist-dir'],
    pocDir: values['poc-dir'],
    now,
    windowDays,
    offline: values.offline,
    knob,
  };
}

const n = (x: number) => x.toLocaleString('en-US');
const pct = (part: number, whole: number) => (whole === 0 ? '0.0%' : `${((100 * part) / whole).toFixed(1)}%`);

export function formatSummary(s: RunSummary): string {
  const { meta } = s;
  const c = meta.counts;
  const lines = [
    '',
    `${BRAND.name} · score model ${meta.score_model} · knob ${meta.knob_default}`,
    `Window ${meta.window.from} → ${meta.window.to} (${meta.window.days} days)`,
    `Published in window: ${n(c.window_published)}  (rejected: ${n(c.rejected_window)}, AI-credited: ${n(c.ai_credited_window)})`,
    ...TIERS.map((t) => `  ${t.padEnd(10)} ${n(c.window_by_tier[t]).padStart(7)}  ${pct(c.window_by_tier[t], c.window_published).padStart(6)}`),
    `Pass rate (exploited + likely): ${pct(c.window_passed, c.window_published)}` +
      (c.window_passed > 0 ? ` — 1 in ${Math.round(c.window_published / c.window_passed)}` : ''),
    `Last 24h: ${n(c.published_24h)} published, ${n(c.passed_24h)} passed · last 7d: ${n(c.published_7d)} published, ${n(c.passed_7d)} passed`,
    `KEV: ${n(c.kev_total)} entries, ${n(c.kev_adds_30d)} added in the last 30 days · batches: ${n(c.batches_window)}`,
    '',
    'Top exploited / likely:',
    ...(s.top.length === 0
      ? ['  (none)']
      : s.top.map((r) => `  ${r.id.padEnd(17)} ${String(r.s).padStart(3)}  ${r.tier.padEnd(9)} ${[r.v, r.p].filter(Boolean).join(' ').slice(0, 40)}`)),
    '',
    'Sources:',
    ...meta.sources.map(
      (src) =>
        `  ${src.id.padEnd(11)} ${(src.ok ? (src.stale ? 'stale' : 'ok') : 'DOWN').padEnd(6)} ${src.records === null ? '' : n(src.records)}` +
        (src.error ? `  (${src.error})` : ''),
    ),
    '',
    `Output: ${s.out} · ${s.validation.files} files · ${s.validation.warnings.length} warnings · ${(s.durationMs / 1000).toFixed(1)} s`,
  ];
  return lines.join('\n');
}

export async function main(argv: string[]): Promise<number> {
  let opts: RunOptions | null;
  try {
    opts = parseCli(argv);
  } catch (e) {
    console.error(`${(e as Error).message}\n\n${USAGE}`);
    return 2;
  }
  if (!opts) {
    console.log(USAGE);
    return 0;
  }
  try {
    console.log(formatSummary(await run(opts)));
    return 0;
  } catch (e) {
    if (e instanceof ValidationFailedError) console.error(formatSizeTable(e.result.sizes));
    console.error(`\npipeline failed: ${(e as Error).stack ?? String(e)}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
