/**
 * Calibration report for a score model (docs/SCORING.md "Calibration", CONTRIBUTING.md).
 *
 *   npm run calibrate -- [--cvelist-dir <clone>] [--poc-dir <clone>] [--cache <dir>] [--now <iso>] [--offline]
 *
 * Runs the pipeline's own ingest and scoreCve() (nothing is re-implemented here) and prints
 * Markdown to stdout; logs go to stderr. Three measurements:
 *   1. tier counts and pass rate of every window CVE at each stop of the site's evidence bar, 35 to 65;
 *   2. KEV recall without KEV: every CVE added to KEV in the current year, re-scored with its own
 *      KEV listing, the CISA-ADP KEV block, SSVC "active" and its EPSS score hidden;
 *   3. the tiers of one patch-day batch (by default the largest in the window).
 * Run it before and after a weight change on the same frozen inputs (--offline --now <instant>).
 */
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { cnaName, isBulkCna } from '../shared/cna';
import { KNOB_DEFAULT, TIERS, tierFor, type Batch, type Tier } from '../shared/contract';
import { SCORE_MODEL } from '../shared/model';
import { assignBatches } from '../pipeline/src/batches';
import { DEFAULT_WINDOW_DAYS } from '../pipeline/src/config';
import { ingest } from '../pipeline/src/ingest';
import { firedChipIds } from '../pipeline/src/rows';
import { buildKevPrior, scoreCve } from '../pipeline/src/score';
import type { Enrichment, IngestResult, NormalizedCve, ScoredCve } from '../pipeline/src/types';
import { DAY_MS, parseIsoDate, ymd } from '../pipeline/src/util/dates';
import { createLogger } from '../pipeline/src/util/log';

/** The stops of the site's evidence bar dial (site/src/state.ts), parameter `knob`. */
export const KNOBS: readonly number[] = [35, 40, 45, 50, 55, 60, 65];

const USAGE = `Usage: npm run calibrate -- [options]

Scores the window and the current year's KEV additions with the pipeline's code and prints a
Markdown calibration report (tiers and pass rate per evidence bar, KEV recall with KEV hidden, one batch).

Options:
  --cache <dir>         Cache of last-good downloads and git clones (default: .cache)
  --cvelist-dir <dir>   Use an existing cvelistV5 git clone (never modified)
  --poc-dir <dir>       Use an existing PoC-in-GitHub git clone (never modified)
  --now <iso>           Freeze "now", e.g. 2026-10-26T19:30:00Z (default: current time)
  --window-days <n>     Window size in days (default: ${DEFAULT_WINDOW_DAYS})
  --year <yyyy>         KEV additions to re-score (default: the year of --now)
  --batch <id>          Batch to break down, e.g. microsoft-2026-10-13 (default: the largest patch day)
  --offline             Never use the network; read the cache only
  -h, --help            Show this help
`;

type Scored = Pick<ScoredCve, 'score' | 'exploited' | 'weaponized'>;
export type TierCounts = Record<Tier, number>;

export function tierCounts(items: readonly Scored[], knob: number): TierCounts {
  const out = Object.fromEntries(TIERS.map((t) => [t, 0])) as TierCounts;
  for (const s of items) out[tierFor(s.score, s.exploited, s.weaponized, knob)]++;
  return out;
}

/** The enrichment buildOutput() (pipeline/src/emit/build.ts) scores with. */
export function enrichmentOf(ing: IngestResult): Enrichment {
  return {
    kev: ing.kev,
    epss: ing.epss,
    exploits: ing.exploits,
    prior: buildKevPrior(ing.kev),
    unavailable: new Map(ing.sources.filter((s) => !s.ok).map((s) => [s.id, s.name])),
  };
}

function without<V>(map: ReadonlyMap<string, V>, key: string): Map<string, V> {
  const copy = new Map(map);
  copy.delete(key);
  return copy;
}

/**
 * A KEV CVE as it looked before anyone confirmed its exploitation: no KEV entry of its own and
 * no CISA-ADP KEV block, SSVC exploitation "active" lowered to "poc" when a public exploit
 * artifact exists (else "none"), and no EPSS score, which reacts to the same exploitation. The
 * KEV prior stays the one built from the full catalogue; scoreCve() never counts the CVE itself.
 */
export function hideExploitation(cve: NormalizedCve, enr: Enrichment): { cve: NormalizedCve; enr: Enrichment } {
  const { metasploit, nuclei, exploitdb, poc } = enr.exploits;
  const artifact =
    [metasploit, nuclei, exploitdb].some((m) => (m.get(cve.id)?.length ?? 0) > 0) || (poc.get(cve.id) ?? []).some((r) => !r.fork);
  const ssvc = cve.ssvc?.exploitation === 'active' ? { ...cve.ssvc, exploitation: artifact ? 'poc' : 'none' } : cve.ssvc;
  return {
    cve: { ...cve, adpKev: null, ssvc },
    enr: {
      ...enr,
      kev: { ...enr.kev, entries: without(enr.kev.entries, cve.id) },
      epss: { ...enr.epss, scores: without(enr.epss.scores, cve.id) },
    },
  };
}

export interface CalibrationInput {
  ing: IngestResult;
  now: Date;
  /** KEV additions of this year (YYYY) are re-scored. */
  year: number;
  /** Batch id to break down; null picks the largest patch day (not a bulk release). */
  batchId: string | null;
}

export interface Calibration {
  window: ScoredCve[];
  /** CVEs added to KEV in `year`, scored with exploitation hidden. */
  kevAdds: ScoredCve[];
  /** KEV additions with no PUBLISHED record in the CVE List. */
  kevMissing: string[];
  /** KEV additions whose SSVC said "active", by the value hideExploitation() lowered it to. */
  ssvcLowered: { poc: number; none: number };
  batch: Batch | null;
  batchMembers: ScoredCve[];
}

export function calibrate({ ing, now, year, batchId }: CalibrationInput): Calibration {
  const enr = enrichmentOf(ing);
  // As buildOutput() does: a frozen --now may predate records in the clone.
  const known = ing.cves.filter((c) => Date.parse(c.published) <= now.getTime());
  const window = known.filter((c) => c.inWindow).map((c) => scoreCve(c, enr, { now }));
  const batches = assignBatches(window);
  const batch =
    (batchId ? batches.find((b) => b.id === batchId) : [...batches].sort((a, b) => b.count - a.count).find((b) => !isBulkCna(b.cna))) ?? null;

  const byId = new Map(known.map((c) => [c.id, c]));
  const today = ymd(now);
  const kevAdds: ScoredCve[] = [];
  const kevMissing: string[] = [];
  const ssvcLowered = { poc: 0, none: 0 };
  for (const k of ing.kev.entries.values()) {
    if (!k.dateAdded.startsWith(`${year}-`) || k.dateAdded > today) continue;
    const cve = byId.get(k.cveID);
    if (!cve) {
      kevMissing.push(k.cveID);
      continue;
    }
    const hidden = hideExploitation(cve, enr);
    if (cve.ssvc?.exploitation === 'active') ssvcLowered[hidden.cve.ssvc?.exploitation === 'poc' ? 'poc' : 'none']++;
    kevAdds.push(scoreCve(hidden.cve, hidden.enr, { now }));
  }
  return { window, kevAdds, kevMissing, ssvcLowered, batch, batchMembers: batch ? window.filter((s) => s.batch === batch.id) : [] };
}

// ── Markdown ───────────────────────────────────────────────────────────────────────────────

const n = (x: number) => x.toLocaleString('en-US');
const pct = (part: number, whole: number) => (whole === 0 ? '–' : `${((100 * part) / whole).toFixed(1)}%`);
const passed = (c: TierCounts) => c.exploited + c.likely;
const knobCell = (knob: number) => (knob === KNOB_DEFAULT ? `**${knob}**` : String(knob));

/** Tier counts per evidence bar; the last column is Exploited + Likely next, as a share (and "1 in N" for volume). */
function tierTable(items: readonly Scored[], lastColumn: 'Passing' | 'Recall'): string[] {
  const lines = [`| Evidence bar | Exploited | Likely next | Watch | Quiet | ${lastColumn} |`, '|--:|--:|--:|--:|--:|--:|'];
  for (const knob of KNOBS) {
    const c = tierCounts(items, knob);
    const p = passed(c);
    const odds = lastColumn === 'Passing' && p > 0 ? ` · 1 in ${Math.round(items.length / p)}` : '';
    lines.push(`| ${knobCell(knob)} | ${TIERS.map((t) => n(c[t])).join(' | ')} | ${n(p)} (${pct(p, items.length)}${odds}) |`);
  }
  return lines;
}

/** Ids of the CVEs among `items` whose fired chips (Row.r) include `chipId`. */
function withChip(items: readonly ScoredCve[], chipId: string): string[] {
  return items.filter((s) => firedChipIds(s.reasons).includes(chipId)).map((s) => s.cve.id);
}

function countBy(items: readonly string[]): string {
  const counts = new Map<string, number>();
  for (const x of items) counts.set(x, (counts.get(x) ?? 0) + 1);
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([k, v]) => `\`${k}\` ${n(v)}`).join(', ');
}

export function formatReport(cal: Calibration, { ing, now, year, windowDays }: CalibrationInput & { windowDays: number }): string {
  const { window, kevAdds, batch, batchMembers } = cal;
  const sources = ing.sources.map((s) => `${s.id} ${s.ok ? (s.stale ? 'stale' : 'ok') : 'DOWN'}${s.upstream_version ? ` (${s.upstream_version.slice(0, 24)})` : ''}`);
  const out = [
    `# Calibration · score model ${SCORE_MODEL} · ${now.toISOString()}`,
    '',
    `Sources: ${sources.join(' · ')}`,
    '',
    `## Window: ${n(window.length)} CVEs published in the last ${windowDays} days`,
    '',
    ...tierTable(window, 'Passing'),
    '',
    `## KEV recall without KEV: ${n(kevAdds.length)} CVEs added to KEV in ${year}`,
    '',
    'Each re-scored without its own KEV entry, the CISA-ADP KEV block, SSVC *active* (lowered to *poc* or *none*) and its',
    'EPSS score; the KEV prior is the rest of the catalogue. Evidence is as observed today, so this is an upper bound.',
    '',
    ...tierTable(kevAdds, 'Recall'),
    '',
    `SSVC *active* lowered to *poc* ${n(cal.ssvcLowered.poc)}, to *none* ${n(cal.ssvcLowered.none)}. ` +
      `Exploited on vendor evidence alone: ${countBy(kevAdds.filter((s) => s.exploited).map((s) => s.reasons[0].id)) || 'none'}.` +
      (cal.kevMissing.length ? ` Not in the CVE List as PUBLISHED: ${cal.kevMissing.join(', ')}.` : ''),
    '',
    '## Evidence bar sensitivity',
    '',
    '| Evidence bar | New CVEs passing | KEV recall |',
    '|--:|--:|--:|',
    ...KNOBS.map((knob) => {
      const w = passed(tierCounts(window, knob));
      const k = passed(tierCounts(kevAdds, knob));
      return `| ${knobCell(knob)} | ${pct(w, window.length)} (${n(w)}) | ${pct(k, kevAdds.length)} (${n(k)} of ${n(kevAdds.length)}) |`;
    }),
  ];
  if (batch) {
    const ids = (chipId: string) => {
      const found = withChip(batchMembers, chipId);
      return found.length ? `${n(found.length)} (${found.join(', ')})` : '0';
    };
    const exploited = batchMembers.filter((s) => s.exploited);
    out.push(
      '',
      `## Batch ${batch.id}: ${cnaName(batch.cna)} · ${batch.date} · ${n(batch.count)} CVEs`,
      '',
      ...tierTable(batchMembers, 'Passing'),
      '',
      `- Exploited: ${n(exploited.length)}${exploited.length ? ` (${exploited.map((s) => `${s.cve.id} via \`${s.reasons[0].id}\``).join(', ')})` : ''}`,
      `- PoC repo on GitHub (\`x.poc\`, the batch card's "PoC" count): ${ids('x.poc')}`,
      `- Vendor CVSS says a PoC exists (\`vendor.poc\`): ${ids('vendor.poc')}`,
      `- Vendor CVSS says working exploit code exists (\`vendor.functional\`): ${ids('vendor.functional')}`,
      `- Weaponized (Metasploit or Nuclei): ${n(batchMembers.filter((s) => s.weaponized).length)}`,
      `- AI-credited: ${n(batchMembers.filter((s) => s.cve.aiCredit !== null).length)}`,
    );
  }
  return out.join('\n');
}

// ── CLI ────────────────────────────────────────────────────────────────────────────────────

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
        'window-days': { type: 'string', default: String(DEFAULT_WINDOW_DAYS) },
        year: { type: 'string' },
        batch: { type: 'string' },
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
  const windowDays = Number(values['window-days']);
  const year = values.year === undefined ? now?.getUTCFullYear() : Number(values.year);
  if (!now || !Number.isInteger(windowDays) || windowDays < 1 || !Number.isInteger(year)) {
    console.error(`--now must be an ISO 8601 date, --window-days and --year whole numbers\n\n${USAGE}`);
    return 2;
  }

  const log = createLogger();
  const windowStart = new Date(now.getTime() - windowDays * DAY_MS);
  const ing = await ingest(
    { now, windowDays, windowStart, cacheDir: values.cache, offline: values.offline, log },
    { cvelistDir: values['cvelist-dir'], pocDir: values['poc-dir'] },
  );
  const input = { ing, now, year: year!, batchId: values.batch ?? null };
  const cal = calibrate(input);
  if (values.batch && !cal.batch) log.warn(`calibrate: no batch ${values.batch} in the window`);
  console.log(formatReport(cal, { ...input, windowDays }));
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
