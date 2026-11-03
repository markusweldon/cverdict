/**
 * The hindsight backtest behind the Receipts page (pipeline/src/backtest.ts), on demand.
 *
 *   npm run backtest -- [--cvelist-dir <clone>] [--poc-dir <clone>] [--cache <dir>] [--now <iso>] [--previous <dir>] [--json <file>] [--offline]
 *
 * For every CISA KEV addition of the last 180 days, it re-scores the CVE with the evidence of the
 * day before the listing (see the header of pipeline/src/backtest.ts for exactly which signals are
 * time-matched and which are hindsight) and asks whether CVErdict, "CVSS 7 or more" and "EPSS 10%
 * or more" would have flagged it. It uses the pipeline's own ingest and scoreCve(), downloads the
 * archived EPSS file of each day before a listing through the cached source machinery, and prints
 * Markdown to stdout (logs go to stderr). The hourly pipeline runs the same code about weekly.
 *
 * This is hindsight: a reconstruction after the fact. The real-time record is the forward log.
 */
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { RECEIPT_METHODS, type BacktestReceipts, type MethodScore, type ReceiptMethod } from '../shared/contract';
import { SCORE_MODEL } from '../shared/model';
import { decideBacktest, readPreviousBacktest, runBacktest } from '../pipeline/src/backtest';
import { DEFAULT_WINDOW_DAYS } from '../pipeline/src/config';
import { ingest } from '../pipeline/src/ingest';
import { toRow } from '../pipeline/src/rows';
import { scoreCve } from '../pipeline/src/score';
import { DAY_MS, parseIsoDate } from '../pipeline/src/util/dates';
import { createLogger } from '../pipeline/src/util/log';
import { enrichmentOf } from './calibrate';

const USAGE = `Usage: npm run backtest -- [options]

Re-scores every CISA KEV addition of the last 180 days with the evidence of the day before its
listing and compares CVErdict with "CVSS 7 or more" and "EPSS 10% or more". Prints Markdown.

Options:
  --cache <dir>         Cache of last-good downloads and git clones (default: .cache)
  --cvelist-dir <dir>   Use an existing cvelistV5 git clone (never modified)
  --poc-dir <dir>       Use an existing PoC-in-GitHub git clone (never modified)
  --now <iso>           Freeze "now", e.g. 2026-11-03T12:00:00Z (default: current time)
  --previous <dir>      A previous output root: EPSS values in its receipts.json are reused
  --json <file>         Also write the result (the receipts.json "backtest" object) to this file
  --offline             Never use the network; read the cache only
  -h, --help            Show this help
`;

const LABEL: Record<ReceiptMethod, string> = { cverdict: 'CVErdict', cvss7: 'CVSS 7 or more', epss10: 'EPSS 10% or more' };
const n = (x: number) => x.toLocaleString('en-US');
const pct = (part: number, whole: number) => (whole === 0 ? '–' : `${((100 * part) / whole).toFixed(1)}%`);

function scoreRow(m: MethodScore | undefined): string {
  return m ? `${n(m.before)} of ${n(m.n)} (${pct(m.before, m.n)})` : '–';
}

export function formatBacktest(b: BacktestReceipts): string {
  const out = [
    `# Hindsight backtest · score model ${SCORE_MODEL} · computed ${b.computed_at}`,
    '',
    `CISA KEV additions from ${b.from} to ${b.to}: ${n(b.listed)}. This is hindsight: each CVE is re-scored with the`,
    'evidence of the day before its listing where the source dates it. "Strict" leaves out every signal without a usable',
    'date; "with undated evidence" adds today\'s value of those signals (usually the higher figure). Neither uses the listing.',
    '',
  ];
  for (const e of b.excluded) out.push(`- Left out (${e.reason}): ${n(e.ids.length)}: ${e.ids.join(', ')}`);
  if (b.epss_missing.length) out.push(`- EPSS file missing for ${b.epss_missing.length} days (EPSS left out for those CVEs): ${b.epss_missing.join(', ')}`);
  for (const set of b.sets) {
    out.push(
      '',
      `## ${set.key === 'recent' ? `Published up to ${b.old_years} years before the listing` : `Published more than ${b.old_years} years before the listing`}: ${n(set.n)}`,
      '',
      '| Method | Flagged before the listing (strict) | With undated evidence |',
      '|---|--:|--:|',
      ...RECEIPT_METHODS.map((m) => `| ${LABEL[m]} | ${scoreRow(set.strict.find((x) => x.method === m))} | ${scoreRow(set.upper.find((x) => x.method === m))} |`),
    );
  }
  if (b.volume) {
    out.push('', `## Alert volume: ${n(b.volume.n)} CVEs published since ${b.volume.from.slice(0, 10)}, with today's evidence`, '');
    out.push('| Method | Flagged |', '|---|--:|', ...b.volume.methods.map((v) => `| ${LABEL[v.method]} | ${n(v.flagged)} (${pct(v.flagged, v.n)}) |`));
  }
  out.push('', '## Signals', '', '| Signal | Treatment | CVEs affected | Note |', '|---|---|--:|---|');
  for (const s of b.signals) out.push(`| ${s.label} | ${s.treatment.replace('_', '-')} | ${n(s.affected)} | ${s.note} |`);
  out.push('', '## Every CVE', '', '| CVE | Listed | Published | CVErdict | CVSS ≥ 7 | EPSS ≥ 10% | Score | Left out |', '|---|---|---|---|---|---|--:|---|');
  const mark = (strict: boolean, upper: boolean) => (strict ? 'yes' : upper ? 'undated only' : 'no');
  for (const i of b.items) {
    out.push(
      `| ${i.id}${i.old ? ' (old)' : ''} | ${i.kev_added} | ${i.published.slice(0, 10)} | ${mark(i.strict.cverdict, i.upper.cverdict)} | ${mark(i.strict.cvss7, i.upper.cvss7)} | ` +
        `${mark(i.strict.epss10, i.upper.epss10)} | ${i.score} | ${i.left_out.join(', ') || '–'} |`,
    );
  }
  return out.join('\n');
}

export async function main(argv: string[]): Promise<number> {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        cache: { type: 'string', default: '.cache' },
        'cvelist-dir': { type: 'string' },
        'poc-dir': { type: 'string' },
        now: { type: 'string' },
        previous: { type: 'string' },
        json: { type: 'string' },
        offline: { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`${(e as Error).message}\n\n${USAGE}`);
    return 2;
  }
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  const now = values.now === undefined ? new Date() : parseIsoDate(values.now);
  if (!now) {
    console.error(`--now must be an ISO 8601 date\n\n${USAGE}`);
    return 2;
  }
  const log = createLogger();
  const { plan } = decideBacktest(readPreviousBacktest(values.previous ?? null), now, true);
  const windowStart = new Date(now.getTime() - DEFAULT_WINDOW_DAYS * DAY_MS);
  const ing = await ingest(
    { now, windowDays: DEFAULT_WINDOW_DAYS, windowStart, cacheDir: values.cache, offline: values.offline, log },
    { cvelistDir: values['cvelist-dir'], pocDir: values['poc-dir'], backtest: plan! },
  );
  if (!ing.backtest) throw new Error('backtest inputs missing');
  const enr = enrichmentOf(ing);
  // As buildOutput() does: a frozen --now may predate records in the clone.
  const all = ing.cves.filter((c) => Date.parse(c.published) <= now.getTime()).map((c) => scoreCve(c, enr, { now }));
  const result = runBacktest({
    now,
    kev: ing.kev,
    cves: new Map(all.map((s) => [s.cve.id, s.cve])),
    enr,
    inputs: ing.backtest,
    scored: all,
    rows: new Map(all.filter((s) => ing.kev.entries.has(s.cve.id)).map((s) => [s.cve.id, toRow(s)])),
  });
  if (values.json) writeFileSync(values.json, JSON.stringify(result));
  console.log(formatBacktest(result));
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
