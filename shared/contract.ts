/**
 * Public data contract shared by the pipeline (producer) and the site (consumer).
 *
 * Everything under `data/v1/` is described here. Changing a field name or meaning is a
 * breaking change: bump SCHEMA_VERSION and the `v1` path segment together.
 */

export const SCHEMA_VERSION = 1;

/** Priority tiers, most to least urgent. */
export type Tier = 'exploited' | 'likely' | 'watch' | 'quiet';
export const TIERS: readonly Tier[] = ['exploited', 'likely', 'watch', 'quiet'];

/** `up` raises priority, `down` lowers it, `info` is context (0 pts), `unknown` is missing evidence (0 pts). */
export type Polarity = 'up' | 'down' | 'info' | 'unknown';

/**
 * Scoring families. Within a family only the strongest chip counts (except SSVC, whose two
 * decision points are independent and add); across families points add. See docs/SCORING.md.
 */
export type Family = 'E' | 'X' | 'SEV' | 'SSVC' | 'PRIOR' | 'NOISE' | 'INFO';

/** Identifier of an upstream source; matches `SourceStatus.id`. */
export type SourceId =
  | 'cvelist'
  | 'cisa-adp'
  | 'kev'
  | 'epss'
  | 'metasploit'
  | 'nuclei'
  | 'exploitdb'
  | 'poc-github'
  /** OSV.dev advisories behind v1/packages.json. Never feeds a score, chip or unknown. */
  | 'osv'
  | 'computed';

/** One human-readable reason ("chip") explaining a score. */
export interface Reason {
  /** Stable chip id, e.g. `kev.listed`, `x.metasploit`. Full catalogue in shared/model.ts. */
  id: string;
  /** Full label, e.g. "CISA KEV · added Oct 21 · due Oct 24". Plain text, never HTML. */
  label: string;
  polarity: Polarity;
  family: Family;
  /** Points this chip actually contributed (0 when it lost to a stronger chip in its family). */
  points: number;
  source: SourceId;
  /** Link to the evidence, when one exists. */
  url?: string;
  /** ISO date/time the evidence is dated (e.g. KEV dateAdded, PoC repo created_at). */
  at?: string;
}

/** Compact row used by list views (signal feed, explore, batches). */
export interface Row {
  /** CVE ID, e.g. "CVE-2026-104596". */
  id: string;
  /** datePublished, ISO 8601 UTC. */
  pub: string;
  /** CNA short name (cveMetadata.assignerShortName). */
  cna: string;
  /** Vendor of the first affected entry ("" if unknown). */
  v: string;
  /** Product of the first affected entry ("" if unknown). */
  p: string;
  /** Title, or the description truncated to 160 chars. Plain text. */
  t: string;
  /** Evidence score 0-100. */
  s: number;
  /** Tier at the default knob (meta.knob_default). Clients re-derive it with tierFor(). */
  tier: Tier;
  /** 1 when any E-family (confirmed exploitation) chip fired. */
  x: 0 | 1;
  /** 1 when a Metasploit module or Nuclei template exists (forces at least `likely`). */
  w: 0 | 1;
  /** 1 when the CVE is in CISA KEV. */
  k: 0 | 1;
  /** 1 when the CNA credits list matches an AI tool/vendor (information only). */
  ai: 0 | 1;
  /** Up to 4 chip ids, strongest first (positive chips before negative). For display. */
  c: string[];
  /**
   * Every chip id that fired for this CVE (including ones that lost within their family),
   * excluding unknown-polarity chips. For filtering; order carries no meaning.
   */
  r: string[];
  /** CVSS base score, if any (CNA preferred, then CISA-ADP). */
  cv: number | null;
  /** EPSS probability 0-1, if scored. */
  e: number | null;
  /** KEV due date (YYYY-MM-DD), if in KEV. */
  kd: string | null;
  /** Batch id (see Batch.id), if this CVE is part of a ≥50-record patch-day cohort. */
  b: string | null;
}

/** Column order used by columnar files (index.json, signal.json). */
export const ROW_COLS = ['id', 'pub', 'cna', 'v', 'p', 't', 's', 'tier', 'x', 'w', 'k', 'ai', 'c', 'r', 'cv', 'e', 'kd', 'b'] as const satisfies readonly (keyof Row)[];

/** Columnar encoding of Row[] — rows[i][j] is the value of column cols[j]. */
export interface RowTable {
  schema_version: number;
  generated_at: string;
  /** Rows included: e.g. "all CVEs published in the window" or "score >= 35 or exploited/weaponized". */
  scope: string;
  cols: typeof ROW_COLS;
  rows: unknown[][];
}

export interface Cvss {
  /** "4.0" | "3.1" | "3.0" | "2.0" */
  version: string;
  score: number;
  severity: string | null;
  vector: string;
  /** Who supplied it: the CNA, or CISA's ADP container. */
  source: 'cna' | 'cisa-adp';
}

export interface Ssvc {
  /** "none" | "poc" | "active" */
  exploitation: string;
  /** "yes" | "no" */
  automatable: string;
  /** "partial" | "total" */
  technical_impact: string;
  version: string | null;
  timestamp: string | null;
}

export interface KevInfo {
  date_added: string;
  due_date: string;
  /** "Known" | "Unknown" */
  ransomware: string;
  /** BOD 26-04 forensic triage flag, when present in the catalog. */
  forensic_triage: boolean | null;
  name: string;
  required_action: string;
  notes: string;
}

export interface EpssInfo {
  score: number;
  percentile: number;
  /** Score date YYYY-MM-DD. */
  date: string;
  /** Model version string from the CSV header, e.g. "v2026.06.15". */
  model: string;
}

export interface ExploitEvidence {
  metasploit: { name: string; fullname: string; rank: number | null; type: string; url: string; date: string | null }[];
  nuclei: { path: string; severity: string | null; url: string }[];
  exploitdb: { id: string; verified: boolean; url: string; date: string | null }[];
  poc: {
    /** Repos listed by PoC-in-GitHub (forks excluded). */
    count: number;
    /** Repos that pass validation (see docs/SCORING.md). */
    vetted: number;
    /** >50 repos within 7 days of the first one: attention, not weaponization. */
    hype: boolean;
    /** Up to 5 repos, most-starred first. Links are unverified and may be malware. */
    top: { url: string; stars: number; created: string }[];
  };
}

/** Full per-CVE record, stored in shards. */
export interface CveDetail {
  id: string;
  /** "PUBLISHED" (rejected records are not emitted). */
  state: string;
  published: string;
  reserved: string | null;
  updated: string | null;
  cna: string;
  title: string | null;
  /** English description, plain text, max 1,000 chars. */
  description: string;
  cvss: Cvss | null;
  cwe: string[];
  /** Up to 10 affected entries. */
  affected: { vendor: string; product: string; purl: string | null }[];
  ssvc: Ssvc | null;
  kev: KevInfo | null;
  epss: EpssInfo | null;
  exploits: ExploitEvidence;
  /** Matched text from the CNA credits when it names an AI tool/vendor. */
  ai_credit: string | null;
  /** CNA tags such as "disputed", "unsupported-when-assigned". */
  tags: string[];
  batch: string | null;
  score: {
    value: number;
    /** Tier at the default knob. */
    tier: Tier;
    /** Score before the E-family floor was applied. */
    raw: number;
    model: string;
  };
  /** All chips, ordered: E, X, SEV, SSVC, PRIOR, NOISE, then INFO/unknown. */
  reasons: Reason[];
  /** Human-readable list of evidence we could not see, e.g. "No CISA SSVC assessment yet". */
  unknowns: string[];
  /** Dated evidence, oldest first. */
  timeline: { at: string; event: string; source: SourceId }[];
  /** Up to 10 reference URLs from the CNA container. */
  references: string[];
  /** Set when the CVE was published before the window and woke up recently (see WokeFile). */
  woke: WokeInfo | null;
}

/** One shard file: data/v1/cve/<shard>.json where shard = shardOf(id). */
export interface CveShard {
  schema_version: number;
  generated_at: string;
  items: Record<string, CveDetail>;
}

export interface SourceStatus {
  id: SourceId;
  name: string;
  url: string;
  ok: boolean;
  /** True when we fell back to a cached copy because the live fetch failed. */
  stale: boolean;
  fetched_at: string | null;
  /** Upstream version marker, e.g. KEV catalogVersion, EPSS model+date, git commit. */
  upstream_version: string | null;
  records: number | null;
  error: string | null;
  license: string;
}

export interface Meta {
  schema_version: number;
  generated_at: string;
  score_model: string;
  knob_default: number;
  window: { from: string; to: string; days: number };
  counts: {
    /** Published (not rejected) CVEs with datePublished inside the window. */
    window_published: number;
    /** Of those, tier exploited or likely at the default knob. */
    window_passed: number;
    window_by_tier: Record<Tier, number>;
    published_24h: number;
    passed_24h: number;
    published_7d: number;
    passed_7d: number;
    /** Calendar month to date (UTC). */
    published_mtd: number;
    published_ytd: number;
    rejected_window: number;
    kev_total: number;
    kev_adds_30d: number;
    kev_adds_mtd: number;
    ai_credited_window: number;
    batches_window: number;
  };
  /** Plain-language definition of every count above. */
  definitions: Record<string, string>;
  sources: SourceStatus[];
}

export interface Batch {
  /** `${slug(cna)}-${YYYY-MM-DD}`, e.g. "microsoft-2026-10-13". */
  id: string;
  cna: string;
  date: string;
  count: number;
  by_tier: Record<Tier, number>;
  /** Most common affected products in the batch (max 8). */
  families: { name: string; count: number; passed: number }[];
  /** Highest-scoring rows in the batch (max 5). */
  top: Row[];
}

export interface BatchesFile {
  schema_version: number;
  generated_at: string;
  min_size: number;
  batches: Batch[];
}

export interface KevEntry {
  id: string;
  vendor: string;
  product: string;
  name: string;
  date_added: string;
  due_date: string;
  ransomware: string;
  forensic_triage: boolean | null;
  description: string;
  required_action: string;
  /** CVE was published inside the window (so it also appears in index.json). */
  in_window: boolean;
  /** Our score for the CVE, if we have its record. */
  score: number | null;
}

export interface KevFile {
  schema_version: number;
  generated_at: string;
  catalog_version: string | null;
  /** Entries added in the last 30 days, or due from 14 days ago onward. Newest first. */
  entries: KevEntry[];
}

export interface StatsFile {
  schema_version: number;
  generated_at: string;
  /** Every month since the first CVE (1999). `reserved` buckets published records by dateReserved. */
  monthly: { month: string; published: number; reserved: number; rejected: number; ai: number; kev_added: number }[];
  /** Window days, oldest first. */
  daily: { date: string; published: number; passed: number; exploited: number }[];
  /** Hour buckets across the window for the waterfall: counts[h] = [exploited, likely, watch, quiet] for hour h after `start`. */
  hourly: { start: string; hours: number; counts: [number, number, number, number][] };
  /** Top CNAs in the window. */
  cnas: { cna: string; count: number; passed: number; no_cvss: number; ssvc_missing: number }[];
  /** Most common AI credit strings in the window. */
  ai_credits: { text: string; count: number }[];
}

export interface Change {
  id: string;
  /** When we first observed the change (pipeline run time). */
  at: string;
  from: Tier | null;
  to: Tier;
  /** Chip ids that appeared since the previous run. */
  added: string[];
}

export interface ChangesFile {
  schema_version: number;
  generated_at: string;
  /** Escalations only (tier went up, or a new E/X chip appeared), last 7 days, newest first. */
  items: Change[];
}

/** Kind of new exploitation evidence that "woke up" an old CVE (see WokeFile). */
export type WakeKind = 'kev' | 'exploitdb' | 'metasploit' | 'nuclei' | 'poc' | 'epss';
export const WAKE_KINDS: readonly WakeKind[] = ['kev', 'exploitdb', 'metasploit', 'nuclei', 'poc', 'epss'];

/** One piece of new evidence for an old CVE. */
export interface WakeSignal {
  kind: WakeKind;
  /**
   * When the evidence appeared. YYYY-MM-DD for KEV dateAdded, Exploit-DB date_added and the EPSS
   * score date; ISO 8601 date-time for a PoC repo's created_at and for first-seen times.
   */
  at: string;
  /**
   * True when `at` is when we first saw the evidence, because the source gives no date
   * (Metasploit, Nuclei) or cannot say when it changed (an EPSS jump between two daily files).
   */
  first_seen: boolean;
  /** Plain text that reads after "Woke up <date>:", e.g. "added to CISA KEV". */
  label: string;
  source: SourceId;
  /** Where to check the evidence, when there is a stable link. */
  url: string | null;
}

/** Why a CVE is in woke.json; also on its CveDetail. */
export interface WokeInfo {
  /** Date of the newest signal (sort key). */
  at: string;
  /** Oldest first. */
  signals: WakeSignal[];
}

export interface WokeItem extends WokeInfo {
  id: string;
  row: Row;
}

/** v1/woke.json: CVEs published before the window that gained exploitation evidence recently. */
export interface WokeFile {
  schema_version: number;
  generated_at: string;
  /** Signals dated on or after this instant count (generated_at minus `days`). */
  since: string;
  days: number;
  /** Only CVEs published before this instant (the start of the 30-day window) are included. */
  published_before: string;
  /**
   * First-seen kinds: since when they are tracked, or null when not tracked yet. Evidence that
   * was already there when tracking started is not shown, so nothing is dated wrongly.
   */
  tracking: { metasploit: string | null; nuclei: string | null; epss: string | null };
  /** Signals this run could not check, and why. Missing data is never read as "nothing new". */
  skipped: { kind: WakeKind; reason: string }[];
  /** Items with at least one signal of each kind. */
  counts: Record<WakeKind, number>;
  /** Newest `at` first. */
  items: WokeItem[];
}

/** Ways of deciding what to patch first that the Receipts page compares (see ReceiptsFile). */
export type ReceiptMethod = 'cverdict' | 'cvss7' | 'epss10';
export const RECEIPT_METHODS: readonly ReceiptMethod[] = ['cverdict', 'cvss7', 'epss10'];

/** Lead time in whole UTC days. Median and quartiles interpolate linearly between ranks. */
export interface LeadDays {
  median: number;
  q1: number;
  q3: number;
}

/** How one method did on one set of CISA KEV additions. Every count shares the same `n`. */
export interface MethodScore {
  method: ReceiptMethod;
  /** KEV additions in the set. */
  n: number;
  /** Flagged before the listing: `earlier` + `same_day`. */
  before: number;
  /** Flagged at least one whole UTC day before the KEV dateAdded. */
  earlier: number;
  /** Flagged on the KEV dateAdded itself, by a run before the one that saw the listing (0 days). */
  same_day: number;
  /** Lead days over the `before` CVEs; null when `before` is 0, and always null in the backtest. */
  lead: LeadDays | null;
}

/** Alert volume: how many CVEs a method flags out of `n`. */
export interface AlertVolume {
  method: ReceiptMethod;
  n: number;
  flagged: number;
}

/**
 * One method's verdict on one KEV addition in the forward log. `earlier` and `same_day` count as
 * flagged before the listing; `after` means it was flagged only at or after the listing; `never`
 * means it was not flagged while we watched it.
 */
export type ReceiptOutcome = 'earlier' | 'same_day' | 'after' | 'never';

export interface ReceiptFlag {
  /** Hour of the first run that flagged the CVE while we watched it (rounded down), or null. */
  at: string | null;
  outcome: ReceiptOutcome;
  /** KEV dateAdded minus the UTC day of `at`, for `earlier` and `same_day`; else null. */
  lead: number | null;
}

/** A KEV addition the forward log can judge: we saw the CVE before CISA listed it. */
export interface ReceiptItem {
  id: string;
  /** KEV dateAdded (YYYY-MM-DD). */
  kev_added: string;
  /** Hour of the first run that saw the CVE (rounded down). */
  first_seen: string;
  flags: Record<ReceiptMethod, ReceiptFlag>;
  /**
   * The CVE as it is scored now, for display; null when its record is not in this run, or when
   * the listing is more than a year old (to keep the file small; the CVE page has it).
   */
  row: Row | null;
}

/** A KEV addition since logging started that the forward log cannot judge, and why. */
export interface UncountedListing {
  id: string;
  kev_added: string;
  /**
   * `older`: the CVE was not in the log, because it was published before the window when the log
   * could have seen it (these are the ones Woke up covers). `listed_first`: the first run that saw
   * the CVE already saw its KEV listing, or saw the CVE only after the listing date. `no_record`:
   * there is no published CVE record for it yet, so no method could have seen it.
   */
  reason: 'older' | 'listed_first' | 'no_record';
}

/** The forward log: real-time observations, recorded run by run, no hindsight. */
export interface ForwardReceipts {
  /** First run of the log. Nothing before it is known. */
  since: string;
  /** Last run that updated the log. */
  last: string;
  runs: number;
  /** Stretches of more than 3 hours without a run (the most recent 50), oldest first. */
  gaps: { from: string; to: string }[];
  /** Every such stretch since `since`, not only the most recent 50: how many, and their hours in all. */
  gap_total: { n: number; hours: number };
  /** Each CVE is watched while it is in the window (its first `watch_days` days, or from `since`). */
  watch_days: number;
  /** KEV additions dated from the `since` day to today. */
  listed: number;
  /** Of those, the CVEs we had seen before the listing: the set `methods` scores. */
  eligible: number;
  methods: MethodScore[];
  /** Out of every CVE the log has watched so far, how many each method flagged at least once. */
  volume: AlertVolume[];
  /** Eligible KEV additions, newest listing first. */
  items: ReceiptItem[];
  /** The other KEV additions since `since`, newest first. */
  uncounted: UncountedListing[];
}

/** How the backtest treated one kind of evidence. */
export interface BacktestSignal {
  key: string;
  label: string;
  /**
   * `time_matched`: only evidence dated before the listing day is used. `hindsight`: the source has
   * no usable date, so the strict scores leave it out and `upper` uses today's value.
   * `excluded`: never used, because it is the listing itself or follows from it.
   * `today`: used as it is today in both variants, because no earlier version can be read
   * (vendor and product names, tags, description text).
   */
  treatment: 'time_matched' | 'hindsight' | 'excluded' | 'today';
  note: string;
  /**
   * Backtest CVEs this touched: for `hindsight` signals, how many the strict scores had to leave
   * out; for `excluded` ones, how many it was set aside or lowered for; for `today` ones, every CVE.
   */
  affected: number;
}

export interface BacktestSet {
  /** `recent`: published at most `old_years` before the listing. `old`: published longer before. */
  key: 'recent' | 'old';
  n: number;
  /** Time-matched evidence only; signals without a usable date are left out. */
  strict: MethodScore[];
  /**
   * The same, plus today's value of every signal without a usable date ("with undated evidence").
   * Usually the higher figure, but not a guaranteed bound: undated evidence can also cost points.
   */
  upper: MethodScore[];
}

export interface BacktestItem {
  id: string;
  kev_added: string;
  published: string;
  old: boolean;
  strict: Record<ReceiptMethod, boolean>;
  upper: Record<ReceiptMethod, boolean>;
  /** CVErdict's score and chips (fired, as in Row.r) with time-matched evidence. */
  score: number;
  chips: string[];
  /** CVSS base score used by the strict scores (null when left out or absent). */
  cvss: number | null;
  /** EPSS score on the day before the listing (null: no score that day, or no file). */
  epss: number | null;
  /** Score date of the EPSS file used, or null when no file for that day could be loaded. */
  epss_date: string | null;
  /** Keys of the signals (BacktestSignal.key) the strict scores had to leave out for this CVE. */
  left_out: string[];
  row: Row | null;
}

/** The hindsight backtest: KEV additions of the last `days` days, re-scored as of the day before. */
export interface BacktestReceipts {
  /** Always true: this is a reconstruction after the fact, not a real-time record. */
  hindsight: true;
  /** When the backtest was computed (it is refreshed about weekly). */
  computed_at: string;
  /**
   * Score model the backtest ran with (absent in copies written before this field existed). A copy
   * from another model is recomputed, never carried forward.
   */
  score_model?: string;
  /** KEV dateAdded range, inclusive. */
  from: string;
  to: string;
  days: number;
  old_years: number;
  /** KEV additions in the range. */
  listed: number;
  /**
   * Additions left out of every figure. `no_record`: no PUBLISHED CVE record. `not_public`: the
   * CVE was published on or after the listing day, so no method could have flagged it before.
   */
  excluded: { code: 'no_record' | 'not_public'; reason: string; ids: string[] }[];
  sets: BacktestSet[];
  /**
   * Alert volume over the same period: CVEs published from `from` on, flagged with today's
   * evidence (hindsight for CVErdict and EPSS). Null when it was not measured.
   */
  volume: { from: string; n: number; methods: AlertVolume[] } | null;
  signals: BacktestSignal[];
  /** Days before a listing whose EPSS file could not be loaded (EPSS left out for those CVEs). */
  epss_missing: string[];
  /**
   * Sources with no usable data when it was computed (their evidence is missing from every figure;
   * it is recomputed a day later). Absent in copies from before the field existed.
   */
  sources_down?: string[];
  items: BacktestItem[];
  /** Command that reproduces the backtest. */
  command: string;
}

/** v1/receipts.json: how often CVErdict flagged a CVE before CISA listed it as exploited. */
export interface ReceiptsFile {
  schema_version: number;
  generated_at: string;
  score_model: string;
  /** Knob the CVErdict method uses (always KNOB_DEFAULT). */
  knob: number;
  /** Plain-language definition of each method and figure. */
  definitions: Record<string, string>;
  forward: ForwardReceipts;
  /** Null until the first backtest has run. */
  backtest: BacktestReceipts | null;
}

/** Package ecosystems in v1/packages.json, named as OSV.dev names them. */
export type PackageEcosystem = 'npm' | 'PyPI' | 'Maven' | 'Go' | 'crates.io' | 'RubyGems' | 'Packagist' | 'NuGet';
export const PACKAGE_ECOSYSTEMS: readonly PackageEcosystem[] = ['npm', 'PyPI', 'Maven', 'Go', 'crates.io', 'RubyGems', 'Packagist', 'NuGet'];

/**
 * One advisory saying that versions of a package are affected by a tracked CVE.
 *
 * `ranges`: one array of events per OSV range. Each event is a string: ">=V" (introduced),
 * "<V" (fixed), "<=V" (last_affected). ">=0" means from the first release. An event of any other
 * kind is written "?kind=V"; a range with one cannot be evaluated ("unknown"). The pipeline also
 * writes the ranges ["?git=unknown"] (only GIT ranges upstream) and ["?versions=capped"] (more
 * than 1,000 listed versions), so those cases read as "not checked", never as "not affected".
 * `versions` (optional): versions the advisory lists as affected that its ranges do not cover or
 * that cannot be compared. They match as exact strings.
 */
export type PackageAffect = [cve: string, advisory: string, ranges: string[][], versions?: string[]];

/** Advisory data for one ecosystem in this run. */
export interface PackageSourceStatus {
  ecosystem: PackageEcosystem;
  /** A copy was available (fresh or cached). When false, the ecosystem has no `packages` entry. */
  ok: boolean;
  /** The live update failed and the last good copy was used. */
  stale: boolean;
  /** When the copy was last brought up to date with OSV.dev. */
  fetched_at: string | null;
  /** Newest OSV `modified` time applied to the copy. */
  modified: string | null;
  /** OSV records of this ecosystem in the copy that name at least one CVE (tracked or not). */
  advisories: number;
  /** Of those, the records that name a CVE in `cves`. */
  matched: number;
  error: string | null;
}

/** An upstream advisory database whose data is in v1/packages.json. */
export interface PackageAttribution {
  name: string;
  url: string;
  license: string;
  /** Advisory ID prefixes from this database, e.g. ["GHSA"]. Records with other prefixes are not published. */
  prefixes: string[];
  /** Notice text a licence requires to travel with copies (the Drupal MIT notice), or null. */
  notice: string | null;
}

/** v1/packages.json: which package versions the tracked CVEs affect, for the in-browser check. */
export interface PackagesFile {
  schema_version: number;
  generated_at: string;
  /** Which CVEs are covered, and what is kept, in words. */
  scope: string;
  attribution: PackageAttribution[];
  /** One per PACKAGE_ECOSYSTEMS entry, in that order. */
  sources: PackageSourceStatus[];
  /** Every CVE named in `packages`, one row each, with the same columns and values as index.json. */
  cves: { cols: typeof ROW_COLS; rows: unknown[][] };
  /** Ecosystem → package key (packageKey() in shared/packages.ts) → affects, by CVE then advisory. */
  packages: Partial<Record<PackageEcosystem, Record<string, PackageAffect[]>>>;
}

/** Tier for a score at a given knob. Shared so the site and pipeline always agree. */
export function tierFor(score: number, exploited: boolean, weaponized: boolean, knob: number): Tier {
  if (exploited) return 'exploited';
  if (weaponized || score >= knob) return 'likely';
  if (score >= WATCH_FLOOR) return 'watch';
  return 'quiet';
}

/** Scores below this are `quiet` regardless of the knob. */
export const WATCH_FLOOR = 25;
export const KNOB_DEFAULT = 50;
export const KNOB_MIN = 30;
export const KNOB_MAX = 80;
/** signal.json contains every row with score >= this, plus all exploited/weaponized rows. */
export const SIGNAL_MIN_SCORE = 35;

export function rowFromColumns(cols: readonly string[], values: unknown[]): Row {
  const out: Record<string, unknown> = {};
  for (let i = 0; i < cols.length; i++) out[cols[i]] = values[i];
  return out as unknown as Row;
}

export function rowsFromTable(table: Pick<RowTable, 'cols' | 'rows'>): Row[] {
  return table.rows.map((r) => rowFromColumns(table.cols, r));
}
