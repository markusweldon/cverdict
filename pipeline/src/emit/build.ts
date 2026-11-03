/**
 * Pure output assembly: an IngestResult in, every output file (path → content) out.
 * Scores all records, assigns batches, builds rows/details, meta, stats, changes, and renders
 * the JSON tree and feeds. The only I/O is reading the previous run for changes.json.
 */
import {
  KNOB_DEFAULT,
  SCHEMA_VERSION,
  SIGNAL_MIN_SCORE,
  TIERS,
  type Batch,
  type BacktestReceipts,
  type Meta,
  type ReceiptsFile,
  type Row,
  type Tier,
  type WokeFile,
} from '../../../shared/contract';
import { BATCH_MIN, SCORE_MODEL } from '../../../shared/model';
import { backtestProblems, runBacktest } from '../backtest';
import { assignBatches, byScoreThenNewest } from '../batches';
import { CHANGES_RETENTION_DAYS, buildChanges } from '../changes';
import { toDetail, toRow } from '../rows';
import { buildKevPrior, scoreCve } from '../score';
import { encodeLog, forwardReceipts, RECEIPTS_SECTION, updateLog } from '../receipts';
import { serializeState, EMPTY_STATE, readSection, STATE_PATH, type LoadedState, type SectionWrite } from '../state';
import { buildStats } from '../stats';
import type { Enrichment, IngestResult, ScoredCve } from '../types';
import { DAY_MS, monthKey, ymd } from '../util/dates';
import { buildWoke, WOKE_SECTION } from '../woke';
import { kevFeed, signalFeed, wokeFeed } from './atom';
import { kevDueCalendar } from './ics';
import { KEV_RECENT_DAYS, PATHS, buildKevFile, buildShards, daysAgo, rowTable, serializeData } from './json';

const HOUR_MS = 3_600_000;
const TOP_SUMMARY = 10;

const isPassed = (t: Tier) => t === 'exploited' || t === 'likely';
const byNewest = (a: ScoredCve, b: ScoredCve) => b.cve.published.localeCompare(a.cve.published) || a.cve.id.localeCompare(b.cve.id);
const inSignal = (s: ScoredCve) => s.score >= SIGNAL_MIN_SCORE || s.exploited || s.weaponized;

interface MetaInput {
  ingest: IngestResult;
  window: ScoredCve[];
  batches: Batch[];
  now: Date;
  windowStart: Date;
  windowDays: number;
  knob: number;
}

function buildMeta({ ingest: ing, window, batches, now, windowStart, windowDays, knob }: MetaInput): Meta {
  const nowMs = now.getTime();
  const since = (ms: number) => window.filter((s) => Date.parse(s.cve.published) >= nowMs - ms);
  const passedIn = (xs: ScoredCve[]) => xs.filter((s) => isPassed(s.tier)).length;
  const byTier = Object.fromEntries(TIERS.map((t) => [t, 0])) as Record<Tier, number>;
  for (const s of window) byTier[s.tier]++;

  const month = monthKey(now);
  const year = month.slice(0, 4);
  let ytd = 0;
  for (const [m, n] of ing.history.published) if (m.startsWith(year) && m <= month) ytd += n;

  const today = ymd(now);
  const kevSince = daysAgo(now, KEV_RECENT_DAYS);
  let kev30 = 0;
  let kevMtd = 0;
  for (const k of ing.kev.entries.values()) {
    if (k.dateAdded > today) continue;
    if (k.dateAdded >= kevSince) kev30++;
    if (k.dateAdded.startsWith(month)) kevMtd++;
  }
  const last24h = since(24 * HOUR_MS);
  const last7d = since(7 * DAY_MS);

  const counts: Meta['counts'] = {
    window_published: window.length,
    window_passed: byTier.exploited + byTier.likely,
    window_by_tier: byTier,
    published_24h: last24h.length,
    passed_24h: passedIn(last24h),
    published_7d: last7d.length,
    passed_7d: passedIn(last7d),
    published_mtd: ing.history.published.get(month) ?? 0,
    published_ytd: ytd,
    rejected_window: ing.rejectedInWindow,
    kev_total: ing.kev.entries.size,
    kev_adds_30d: kev30,
    kev_adds_mtd: kevMtd,
    ai_credited_window: window.filter((s) => s.cve.aiCredit !== null).length,
    batches_window: batches.length,
  };
  const definitions: Record<keyof Meta['counts'], string> = {
    window_published: `CVE records in PUBLISHED state whose datePublished is within the last ${windowDays} days.`,
    window_passed: `Of those, the ones in the Exploited or Likely-next tier at the default knob (${knob}).`,
    window_by_tier: `Window CVEs per tier at the default knob (${knob}).`,
    published_24h: 'CVEs published in the last 24 hours.',
    passed_24h: 'Of those, Exploited or Likely next at the default knob.',
    published_7d: 'CVEs published in the last 7 days.',
    passed_7d: 'Of those, Exploited or Likely next at the default knob.',
    published_mtd: 'CVEs published since the start of the current calendar month (UTC).',
    published_ytd: 'CVEs published since January 1 of the current year (UTC).',
    rejected_window: `REJECTED records dated within the last ${windowDays} days (not shown anywhere else).`,
    kev_total: 'Entries in the CISA Known Exploited Vulnerabilities catalog.',
    kev_adds_30d: `KEV entries added in the last ${KEV_RECENT_DAYS} days (by dateAdded).`,
    kev_adds_mtd: 'KEV entries added since the start of the current calendar month (UTC).',
    ai_credited_window: 'Window CVEs whose CNA credits name an AI system or AI lab (information only).',
    batches_window: `Batches in the window (patch days and bulk releases): ${BATCH_MIN}+ CVEs from one CNA on one UTC day.`,
  };

  return {
    schema_version: SCHEMA_VERSION,
    generated_at: now.toISOString(),
    score_model: SCORE_MODEL,
    knob_default: knob,
    window: { from: windowStart.toISOString(), to: now.toISOString(), days: windowDays },
    counts,
    definitions,
    sources: ing.sources,
  };
}

export interface BuildInput {
  ingest: IngestResult;
  now: Date;
  windowDays: number;
  knob: number;
  /** Previous output root for changes.json, if any. */
  previous: string | null;
  /** The previous run's state file; its sections nobody rewrites are carried over. */
  previousState?: LoadedState;
  /** Public site base for feed links. */
  siteUrl: string;
  /** The backtest carried forward from the previous receipts.json (used when this run does not refresh it). */
  backtest?: BacktestReceipts | null;
  /** The previous receipts.json's backtest, kept when a refresh cannot read the KEV catalog. */
  previousBacktest?: BacktestReceipts | null;
}

export interface BuiltOutput {
  /** Relative path → file content. */
  files: Map<string, string>;
  meta: Meta;
  batches: Batch[];
  /** Exploited first, then likely; highest score first (max TOP_SUMMARY). */
  top: Row[];
  scored: ScoredCve[];
  woke: WokeFile;
  receipts: ReceiptsFile;
  /** Log lines (receipts and backtest). */
  notes: string[];
}

/** Score the ingested records and render every output file in memory. Reads only `previous`. */
export function buildOutput({
  ingest: ing,
  now,
  windowDays,
  knob,
  previous,
  previousState = EMPTY_STATE,
  siteUrl: base,
  backtest: carried = null,
  previousBacktest = null,
}: BuildInput): BuiltOutput {
  const windowStart = new Date(now.getTime() - windowDays * DAY_MS);
  const unavailable = new Map(ing.sources.filter((s) => !s.ok).map((s) => [s.id, s.name]));
  const enr: Enrichment = { kev: ing.kev, epss: ing.epss, exploits: ing.exploits, prior: buildKevPrior(ing.kev), unavailable };
  // A frozen --now may predate records in the clone: those do not exist yet from our point of view.
  const all = ing.cves.filter((c) => Date.parse(c.published) <= now.getTime()).map((c) => scoreCve(c, enr, { now, knob }));
  const woke = buildWoke(all, ing.wake, now, windowStart);
  // Wake candidates that did not qualify (published in the window, or kept for nothing else) are
  // dropped here, so the shards hold window ∪ KEV ∪ woke records.
  const scored = all.filter((s) => s.cve.inWindow || s.cve.adpKev !== null || ing.kev.entries.has(s.cve.id) || woke.ids.has(s.cve.id));
  const window = scored.filter((s) => s.cve.inWindow);
  const batches = assignBatches(scored);

  const generatedAt = now.toISOString();
  const indexRows = [...window].sort(byNewest).map(toRow);
  const signalRows = window.filter(inSignal).sort(byScoreThenNewest).map(toRow);
  const details = scored.map(toDetail);
  const byId = new Map(scored.map((s) => [s.cve.id, s]));
  const kev = buildKevFile(ing.kev, byId, now);
  const meta = buildMeta({ ingest: ing, window, batches, now, windowStart, windowDays, knob });
  const stats = buildStats({ history: ing.history, kev: ing.kev, window, windowStart, now });
  const recentKevElsewhere = scored
    .filter((s) => !s.cve.inWindow && s.kev && s.kev.date_added >= daysAgo(now, CHANGES_RETENTION_DAYS))
    .map(toRow);
  const changes = buildChanges([...indexRows, ...recentKevElsewhere], previous, now);

  const files = serializeData({
    meta,
    signal: rowTable(signalRows, `score >= ${SIGNAL_MIN_SCORE} or exploited/weaponized; published in the last ${windowDays} days`, generatedAt),
    index: rowTable(indexRows, `all CVEs published in the last ${windowDays} days`, generatedAt),
    shards: buildShards(details, generatedAt),
    batches: { schema_version: SCHEMA_VERSION, generated_at: generatedAt, min_size: BATCH_MIN, batches },
    kev,
    stats,
    changes,
    woke: woke.file,
  });
  // Receipts: the forward log (state section) and the backtest (refreshed or carried forward).
  const notes: string[] = [];
  const r0 = performance.now();
  const logUpdate = updateLog(readSection(previousState, RECEIPTS_SECTION), scored, ing.kev, now);
  const rowById = new Map(scored.map((s) => [s.cve.id, toRow(s)]));
  let backtest = carried;
  if (ing.backtest && unavailable.has('kev')) {
    // Without the catalog there are no listings to judge: keep the last backtest rather than publish
    // an empty one for a week. The next run tries again.
    backtest = previousBacktest && backtestProblems(previousBacktest).length === 0 ? previousBacktest : null;
    notes.push(`backtest: not refreshed, ${unavailable.get('kev')} has no data (${backtest ? `kept the one computed ${backtest.computed_at}` : 'none to keep'})`);
  } else if (ing.backtest) {
    const t0 = performance.now();
    backtest = runBacktest({ now, kev: ing.kev, cves: new Map(all.map((s) => [s.cve.id, s.cve])), enr, inputs: ing.backtest, scored: all, rows: rowById });
    notes.push(`backtest: ${backtest.items.length} of ${backtest.listed} KEV additions since ${backtest.from} re-scored in ${Math.round(performance.now() - t0)} ms`);
  }
  const receipts: ReceiptsFile = {
    schema_version: SCHEMA_VERSION,
    generated_at: generatedAt,
    score_model: SCORE_MODEL,
    knob: KNOB_DEFAULT,
    definitions: RECEIPT_DEFINITIONS,
    forward: forwardReceipts(logUpdate.log, ing.kev, rowById, now, windowDays),
    backtest,
  };
  files.set(PATHS.receipts, JSON.stringify(receipts));
  const writes: SectionWrite[] = [{ key: WOKE_SECTION.key, version: WOKE_SECTION.version, data: ing.wake.state }];
  // A log carried over unchanged is left to serializeState, which copies the previous section verbatim.
  if (logUpdate.updated) writes.push({ key: RECEIPTS_SECTION.key, version: RECEIPTS_SECTION.version, data: encodeLog(logUpdate.log) });
  files.set(STATE_PATH, serializeState(now, writes, previousState));
  notes.push(...logUpdate.notes.map((n) => `receipts: ${n}`), `receipts: log, figures and state in ${Math.round(performance.now() - r0)} ms`);
  const feedOpts = { siteUrl: base, now };
  files.set(PATHS.signalFeed, signalFeed(details.filter((d) => byId.get(d.id)?.cve.inWindow), feedOpts));
  files.set(PATHS.kevFeed, kevFeed(kev.entries, feedOpts));
  files.set(PATHS.kevDueIcs, kevDueCalendar(kev.entries, feedOpts));
  files.set(PATHS.wokeFeed, wokeFeed(woke.file, feedOpts));

  const top = window
    .filter((s) => isPassed(s.tier))
    .sort((a, b) => TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier) || byScoreThenNewest(a, b))
    .slice(0, TOP_SUMMARY)
    .map(toRow);
  return { files, meta, batches, top, scored, woke: woke.file, receipts, notes };
}

/** receipts.json `definitions`: what each method and figure means, in plain words. */
export const RECEIPT_DEFINITIONS: Record<string, string> = {
  cverdict: `CVErdict: the CVE is in the Exploited or Likely next tier at the default knob (${KNOB_DEFAULT}).`,
  cvss7: 'CVSS 7 or more: the CVSS base score the site shows (from the CNA, else CISA-ADP) is 7.0 or higher.',
  epss10: 'EPSS 10% or more: the EPSS score is 0.1 or higher. A CVE without an EPSS score is not flagged.',
  before: 'Flagged before the listing: a run earlier than the one that first saw the CISA KEV listing flagged the CVE, on or before the KEV dateAdded.',
  same_day: 'Same day: flagged on the KEV dateAdded itself, before the listing appeared. Counted as 0 days, separately from earlier.',
  eligible: 'Counted: KEV additions dated since the log started, for CVEs the log saw before the listing.',
  lead: "Lead time: the KEV dateAdded minus the day of the first flag, both read as US Eastern days (CISA's time zone), in whole days. Median and quartiles interpolate between ranks.",
  volume: 'Alert volume: the share of the CVEs a method watched or scored that it flagged.',
  watch: 'Each CVE is watched while it is in the window. A method that flags it only later is not counted.',
};
