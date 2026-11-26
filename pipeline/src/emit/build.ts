/**
 * Pure output assembly: an IngestResult in, every output file (path → content) out.
 * Scores all records, assigns batches, builds rows/details, meta, stats, changes, and renders
 * the JSON tree and feeds. The only I/O is reading the previous run (changes.json, events.json, meta.json).
 */
import {
  KNOB_DEFAULT,
  NON_SCORING_SOURCES,
  SCHEMA_VERSION,
  SIGNAL_MIN_SCORE,
  TIERS,
  type Batch,
  type BacktestReceipts,
  type EventsFile,
  type Meta,
  type ReceiptsFile,
  type PackagesFile,
  type Row,
  type SourceId,
  type SourceStatus,
  type Tier,
  type WokeFile,
} from '../../../shared/contract';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { BRAND } from '../../../shared/brand';
import { BATCH_MIN, SCORE_MODEL } from '../../../shared/model';
import { backtestProblems, runBacktest } from '../backtest';
import { assignBatches, byScoreThenNewest } from '../batches';
import { CHANGES_RETENTION_DAYS, buildChanges, diffRuns } from '../changes';
import { buildEvents, catalogSnapshot, EVENTS_SECTION, readPreviousEvents } from '../events';
import { buildPackagesFile, olderPackagesScope, osvCveIds, slimRow } from '../packages';
import { toDetail, toRow } from '../rows';
import { buildKevPrior, scoreCve } from '../score';
import { encodeLog, forwardReceipts, RECEIPTS_SECTION, updateLog } from '../receipts';
import { serializeState, EMPTY_STATE, readSection, STATE_PATH, type LoadedState, type SectionWrite } from '../state';
import { buildStats, buildSurge } from '../stats';
import { firstExploitedListing, isExploitedListing } from '../sources/catalogs';
import type { CatalogListing, Enrichment, IngestResult, ScoredCve } from '../types';
import { DAY_MS, monthKey, ymd } from '../util/dates';
import { buildWoke, WOKE_SECTION } from '../woke';
import { eventsFeed, kevFeed, signalFeed, wokeFeed } from './atom';
import { kevDueCalendar } from './ics';
import { KEV_RECENT_DAYS, PATHS, buildKevFile, buildShards, daysAgo, rowTable, serializeData } from './json';

const HOUR_MS = 3_600_000;
const TOP_SUMMARY = 10;

const isPassed = (t: Tier) => t === 'exploited' || t === 'likely';

/** Their outages must not change any CVE's output, so they are left out of Enrichment.unavailable. */
export { NON_SCORING_SOURCES };

/**
 * Sources that feed only information chips (0 points, no tier): an outage cannot change a verdict,
 * so it is not reported as unknown evidence on every CVE or in the backtest's `sources_down`. They
 * stay in meta.sources, so the Method page and the header still show their health.
 */
export const INFO_ONLY_SOURCES: ReadonlySet<SourceId> = new Set<SourceId>(['siberkapan']);

/** Enrichment.unavailable: the failed sources whose evidence a verdict depends on (id → name). */
export function unavailableSources(sources: readonly SourceStatus[]): Map<SourceId, string> {
  return new Map(sources.filter((s) => !s.ok && !NON_SCORING_SOURCES.has(s.id) && !INFO_ONLY_SOURCES.has(s.id)).map((s) => [s.id, s.name]));
}
/**
 * CVE IDs with an exploited listing (an E chip) in EU KEV or CIRCL. They are kept whatever their
 * age, like CISA KEV's, so each has a CVE page; they have no CISA due date.
 */
export function exploitedElsewhere(catalogs: ReadonlyMap<string, CatalogListing[]> | undefined, now: Date): Set<string> {
  const out = new Set<string>();
  const day = ymd(now);
  for (const [id, list] of catalogs ?? []) if (list.some((l) => isExploitedListing(l, day))) out.add(id);
  return out;
}

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
    window_passed: `Of those, the ones in the Exploited or Likely-next tier at the default evidence bar (${knob}).`,
    window_by_tier: `Window CVEs per tier at the default evidence bar (${knob}).`,
    published_24h: 'CVEs published in the last 24 hours.',
    passed_24h: 'Of those, Exploited or Likely next at the default evidence bar.',
    published_7d: 'CVEs published in the last 7 days.',
    passed_7d: 'Of those, Exploited or Likely next at the default evidence bar.',
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
  packages: PackagesFile;
  packagesOlder: PackagesFile;
  events: EventsFile;
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
  const unavailable = unavailableSources(ing.sources);
  const enr: Enrichment = { kev: ing.kev, epss: ing.epss, exploits: ing.exploits, prior: buildKevPrior(ing.kev), unavailable };
  // A frozen --now may predate records in the clone: those do not exist yet from our point of view.
  const all = ing.cves.filter((c) => Date.parse(c.published) <= now.getTime()).map((c) => scoreCve(c, enr, { now, knob }));
  const woke = buildWoke(all, ing.wake, now, windowStart, ing.exploits.catalogs);
  // Wake candidates that did not qualify (published in the window, or kept for nothing else) are
  // dropped here, so the shards hold window ∪ KEV ∪ exploited-catalog ∪ woke records.
  const listedElsewhere = exploitedElsewhere(ing.exploits.catalogs, now);
  const scored = all.filter(
    (s) => s.cve.inWindow || s.cve.adpKev !== null || ing.kev.entries.has(s.cve.id) || listedElsewhere.has(s.cve.id) || woke.ids.has(s.cve.id),
  );
  const window = scored.filter((s) => s.cve.inWindow);
  const batches = assignBatches(scored);

  const generatedAt = now.toISOString();
  const indexRows = [...window].sort(byNewest).map(toRow);
  const signalRows = window.filter(inSignal).sort(byScoreThenNewest).map(toRow);
  const details = scored.map(toDetail);
  const byId = new Map(scored.map((s) => [s.cve.id, s]));
  const kev = buildKevFile(ing.kev, byId, now);
  const meta = buildMeta({ ingest: ing, window, batches, now, windowStart, windowDays, knob });
  const outside = scored.filter((s) => !s.cve.inWindow);
  const stats = buildStats({ history: ing.history, kev: ing.kev, window, windowStart, now, catalogs: ing.exploits.catalogs, outside });
  const surge = buildSurge(
    ing.history,
    scored.filter((s) => ing.kev.entries.has(s.cve.id)),
    now,
  );
  const recentDay = daysAgo(now, CHANGES_RETENTION_DAYS);
  const recentKevElsewhere = scored.filter((s) => !s.cve.inWindow && s.kev && s.kev.date_added >= recentDay).map(toRow);
  // Outside the window and not in CISA KEV, first listed as exploited by EU KEV or CIRCL lately.
  // No previous file lists them, so their listing date tells a new arrival.
  const recentCatalogElsewhere = scored
    .filter((s) => !s.cve.inWindow && !s.kev && !s.cve.adpKev && (firstExploitedListing(ing.exploits.catalogs?.get(s.cve.id), ymd(now))?.added ?? '') >= recentDay)
    .map(toRow);
  const compared = [...indexRows, ...recentKevElsewhere, ...recentCatalogElsewhere];
  const freshElsewhere = new Set(recentCatalogElsewhere.map((r) => r.id));
  const runDiff = diffRuns(compared, previous, freshElsewhere);
  const changes = buildChanges(compared, previous, now, freshElsewhere, runDiff);

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
  if (surge) files.set(PATHS.surge, JSON.stringify(surge));
  const p0 = performance.now();
  const packages = buildPackagesFile(ing.osv, rowById, generatedAt, windowDays);
  files.set(PATHS.packages, JSON.stringify(packages));
  // Every other CVE an advisory names: scored like the rest, kept only for the dependency check.
  const named = osvCveIds(ing.osv);
  const olderRows = new Map(all.filter((s) => named.has(s.cve.id) && !rowById.has(s.cve.id) && !s.cve.inWindow).map((s) => [s.cve.id, slimRow(toRow(s))]));
  const packagesOlder = buildPackagesFile(ing.osv, olderRows, generatedAt, windowDays, olderPackagesScope(windowDays));
  files.set(PATHS.packagesOlder, JSON.stringify(packagesOlder));
  notes.push(`packages: ${packages.cves.rows.length} tracked and ${packagesOlder.cves.rows.length} older CVEs named by OSV.dev advisories, built in ${Math.round(performance.now() - p0)} ms`);
  // Verdict events: this run against the previous tree, plus dated causes, deduped by key.
  const status = (id: SourceId) => ing.sources.find((x) => x.id === id);
  const kevStatus = status('kev');
  const euStatus = status('eu-kev');
  const health = eventsHealth(previous, unavailable, woke.file, runDiff?.previousAt ?? null);
  const events = buildEvents({
    now,
    byId,
    rows: rowById,
    diff: runDiff,
    baseline: health.baseline,
    wokeAfter: health.wokeAfter,
    previous: readPreviousEvents(previous),
    previousState: readSection(previousState, EVENTS_SECTION),
    kev: ing.kev,
    catalogs: ing.exploits.catalogs,
    woke: woke.file,
    snapshots: {
      kev: kevStatus?.ok ? catalogSnapshot(ing.kev.entries.keys(), ing.kev.version, kevStatus.fetched_at) : null,
      eu_kev: euStatus?.ok ? catalogSnapshot(ing.euKevIds ?? null, null, euStatus.fetched_at) : null,
    },
  });
  files.set(PATHS.events, JSON.stringify(events.file));
  notes.push(...events.notes.map((n) => `events: ${n}`));
  const writes: SectionWrite[] = [
    { key: WOKE_SECTION.key, version: WOKE_SECTION.version, data: ing.wake.state },
    { key: EVENTS_SECTION.key, version: EVENTS_SECTION.version, data: events.state },
  ];
  // A log carried over unchanged is left to serializeState, which copies the previous section verbatim.
  if (logUpdate.updated) writes.push({ key: RECEIPTS_SECTION.key, version: RECEIPTS_SECTION.version, data: encodeLog(logUpdate.log) });
  files.set(STATE_PATH, serializeState(now, writes, previousState));
  notes.push(...logUpdate.notes.map((n) => `receipts: ${n}`), `receipts: log, figures and state in ${Math.round(performance.now() - r0)} ms`);
  // IDs keep the first public address (BRAND.feedIdBase); links follow the site.
  const feedOpts = { siteUrl: base, idBase: BRAND.feedIdBase, now };
  files.set(PATHS.signalFeed, signalFeed(details.filter((d) => byId.get(d.id)?.cve.inWindow), feedOpts));
  files.set(PATHS.kevFeed, kevFeed(kev.entries, feedOpts));
  files.set(PATHS.kevDueIcs, kevDueCalendar(kev.entries, feedOpts));
  files.set(PATHS.wokeFeed, wokeFeed(woke.file, feedOpts));
  files.set(PATHS.eventsFeed, eventsFeed(events.file, feedOpts));

  const top = window
    .filter((s) => isPassed(s.tier))
    .sort((a, b) => TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier) || byScoreThenNewest(a, b))
    .slice(0, TOP_SUMMARY)
    .map(toRow);
  return { files, meta, batches, top, scored, woke: woke.file, receipts, packages, packagesOlder, events: events.file, notes };
}

/** The scoring sources that were down in the previous run (from its meta.json), by name. */
export function previousSourcesDown(previous: string | null): string[] {
  if (!previous) return [];
  try {
    const meta = JSON.parse(readFileSync(join(previous, PATHS.meta), 'utf8')) as { sources?: unknown };
    if (!Array.isArray(meta.sources)) return [];
    const valid = meta.sources.filter((s): s is SourceStatus => typeof s === 'object' && s !== null && typeof s.id === 'string' && typeof s.ok === 'boolean');
    return [...unavailableSources(valid).values()];
  } catch {
    return [];
  }
}

/** Whether the previous run's woke.json could not check some signals (its `skipped`). */
function previousWokeSkipped(previous: string | null): boolean {
  if (!previous) return false;
  try {
    const w = JSON.parse(readFileSync(join(previous, PATHS.woke), 'utf8')) as { skipped?: unknown };
    return Array.isArray(w.skipped) && w.skipped.length > 0;
  } catch {
    return false;
  }
}

/**
 * How far this run's events can trust the comparison with the previous run.
 *
 * `baseline`: the chip and tier comparison starts from a baseline when the score model changed, or
 * when a scoring source was down in this run or the previous one. A down exploit feed turns "no
 * exploit" into "unknown" (scores rise), and its return brings the chips back: neither is news.
 *
 * `wokeAfter`: when a source was down or woke.json skipped a check, in either run, woke.json can
 * list CVEs it would normally leave out (their older evidence could not be seen). Woke events
 * then only count when the signal is dated after the previous run.
 */
export function eventsHealth(
  previous: string | null,
  unavailable: ReadonlyMap<SourceId, string>,
  woke: WokeFile,
  previousAt: string | null,
): { baseline: string | null; wokeAfter: string | null } {
  const model = modelChange(previous);
  const nowDown = [...unavailable.values()];
  const prevDown = previousSourcesDown(previous);
  const parts: string[] = [];
  if (nowDown.length) parts.push(`down this run: ${nowDown.join(', ')}`);
  if (prevDown.length) parts.push(`down last run: ${prevDown.join(', ')}`);
  const baseline = model ?? (parts.length ? `sources ${parts.join('; ')}` : null);
  const wokeUnsure = parts.length > 0 || woke.skipped.length > 0 || previousWokeSkipped(previous);
  return { baseline, wokeAfter: wokeUnsure && previousAt ? previousAt : null };
}

/** "score model v0.3.0 → v0.4.0" when the previous run scored with another model, else null. */
export function modelChange(previous: string | null): string | null {
  if (!previous) return null;
  let model: unknown;
  try {
    model = (JSON.parse(readFileSync(join(previous, PATHS.meta), 'utf8')) as { score_model?: unknown }).score_model;
  } catch {
    return null;
  }
  return typeof model === 'string' && model !== SCORE_MODEL ? `score model ${model} → ${SCORE_MODEL}` : null;
}

/** receipts.json `definitions`: what each method and figure means, in plain words. */
export const RECEIPT_DEFINITIONS: Record<string, string> = {
  cverdict: `CVErdict: the CVE is in the Exploited or Likely next tier at the default evidence bar (${KNOB_DEFAULT}).`,
  cvss7: 'CVSS 7 or more: the CVSS base score the site shows (from the CNA, else CISA-ADP) is 7.0 or higher.',
  epss10: 'EPSS 10% or more: the EPSS score is 0.1 or higher. A CVE without an EPSS score is not flagged.',
  before: 'Flagged before the listing: a run earlier than the one that first saw the CISA KEV listing flagged the CVE, on or before the KEV dateAdded.',
  same_day: 'Same day: flagged on the KEV dateAdded itself, before the listing appeared. Counted as 0 days, separately from earlier.',
  eligible: 'Counted: KEV additions dated since the log started, for CVEs the log saw before the listing.',
  lead: "Lead time: the KEV dateAdded minus the day of the first flag, both read as US Eastern days (CISA's time zone), in whole days. Median and quartiles interpolate between ranks.",
  volume: 'Alert volume: the share of the CVEs a method watched or scored that it flagged.',
  watch: 'Each CVE is watched while it is in the window. A method that flags it only later is not counted.',
};
