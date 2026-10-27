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
