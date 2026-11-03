/**
 * Internal contracts between pipeline stages:
 *   ingest (sources + normalisation) → score/rows → batches/stats/changes → emit.
 * Public output types live in shared/contract.ts.
 */
import type {
  Cvss,
  CveDetail,
  EpssInfo,
  ExploitEvidence,
  KevInfo,
  Reason,
  SourceId,
  SourceStatus,
  Ssvc,
  Tier,
  WokeInfo,
} from '../../shared/contract';

import type { LoadedState } from './state';
import type { BacktestInputs, BacktestPlan } from './backtest';
import type { WakeDetection } from './woke';

export interface Logger {
  info(msg: string): void;
  warn(msg: string): void;
  error(msg: string): void;
}

export interface RunContext {
  now: Date;
  windowDays: number;
  /** now - windowDays. Records with datePublished >= windowStart are "in the window". */
  windowStart: Date;
  cacheDir: string;
  offline: boolean;
  log: Logger;
}

export interface IngestOptions {
  /** Use this existing cvelistV5 clone instead of cloning/fetching (never modified). */
  cvelistDir?: string;
  /** Use this existing PoC-in-GitHub clone instead of cloning/fetching (never modified). */
  pocDir?: string;
  /** State carried from the previous run (state.ts); missing means a fresh start. */
  previousState?: LoadedState;
  /** Refresh the hindsight backtest this run (backtest.ts); omitted on normal runs. */
  backtest?: BacktestPlan;
}

/** A CVE record reduced to what scoring and display need. All text is sanitised plain text. */
export interface NormalizedCve {
  id: string;
  published: string;
  reserved: string | null;
  updated: string | null;
  cna: string;
  title: string | null;
  /** English description, sanitised, ≤ 1,000 chars. */
  description: string;
  /** Chosen CVSS (CNA v4.0 > v3.1 > v3.0 > v2.0, else CISA-ADP v3.1). */
  cvss: Cvss | null;
  /** Parsed vector of `cvss` (e.g. { AV: 'N', AC: 'L', ... }). */
  cvssMetrics: Record<string, string>;
  /** True when the CNA container itself had no CVSS v3/v4 metric. */
  cnaCvssMissing: boolean;
  /** Exploit-maturity values (the `E` metric) found in CNA vectors; empty for VulDB. e.g. ['U'], ['F'], ['P'], ['A']. */
  cnaExploitMaturity: string[];
  /** CISA-ADP SSVC, values lower-cased. */
  ssvc: Ssvc | null;
  /** CISA-ADP "kev" metric block, if present. */
  adpKev: { dateAdded: string | null; reference: string | null } | null;
  cwe: string[];
  affected: { vendor: string; product: string; purl: string | null }[];
  tags: string[];
  references: string[];
  /** Matched AI credit text (≤ 80 chars), if any. */
  aiCredit: string | null;
  /** Description says the bug is/was exploited in the wild (negations excluded). */
  vendorInTheWild: boolean;
  /** Lower-cased title + description + affected vendor/product + reference URLs, ≤ 4 KB. For noise heuristics. */
  noiseText: string;
  /** providerMetadata.dateUpdated of the CNA container: when the CNA last changed its part of the record. */
  cnaUpdated: string | null;
  /** providerMetadata.dateUpdated of the CISA-ADP container, if there is one. */
  adpUpdated: string | null;
  /** datePublished >= windowStart. (KEV CVEs outside the window are also ingested, with inWindow=false.) */
  inWindow: boolean;
}

/** Raw KEV catalog entry (as published by CISA; unknown extra fields ignored). */
export interface KevRaw {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
  cwes?: string[];
  /** BOD 26-04 field ("Yes" / "No"); absent in older catalogs. */
  forensicTriage?: string;
}

export interface KevCatalog {
  version: string | null;
  dateReleased: string | null;
  entries: Map<string, KevRaw>;
}

export interface EpssTable {
  model: string | null;
  /** YYYY-MM-DD */
  scoreDate: string | null;
  scores: Map<string, { epss: number; percentile: number }>;
}

export interface PocRepo {
  url: string;
  stars: number;
  created: string;
  fork: boolean;
  /** Last push (GitHub pushed_at): the repo's content is only known to predate this. */
  pushed?: string | null;
}

/** Parsed Exploit-DB file. */
export interface ExploitDbData {
  byCve: ExploitIndex['exploitdb'];
  /** Per CVE: the entry Exploit-DB added first (date_added, else date_published). */
  firstAdded: Map<string, { date: string; id: string; url: string }>;
  /** Exploit-DB id → date_added, when the file has that column (the backtest dates entries by it). */
  added: Map<string, string>;
}

/** Parsed Metasploit metadata. */
export interface MetasploitData {
  byCve: ExploitIndex['metasploit'];
  /**
   * Per CVE: the earliest `mod_time` of a module referencing it. A module can only have been
   * modified once it existed, so it existed by then (the backtest's only usable Metasploit date).
   */
  firstModified: Map<string, string>;
}

export interface ExploitIndex {
  metasploit: Map<string, ExploitEvidence['metasploit']>;
  nuclei: Map<string, ExploitEvidence['nuclei']>;
  exploitdb: Map<string, ExploitEvidence['exploitdb']>;
  /** Repos per CVE id (only for ids we ingested). */
  poc: Map<string, PocRepo[]>;
}

/** Month keys are "YYYY-MM". */
export interface History {
  published: Map<string, number>;
  reserved: Map<string, number>;
  rejected: Map<string, number>;
  ai: Map<string, number>;
  totalRecords: number;
}

export interface IngestResult {
  /** Window records ∪ KEV records (deduplicated). */
  cves: NormalizedCve[];
  history: History;
  /** REJECTED records whose date falls in the window. */
  rejectedInWindow: number;
  kev: KevCatalog;
  epss: EpssTable;
  exploits: ExploitIndex;
  sources: SourceStatus[];
  cvelistCommit: string | null;
  /** Wake signals found in the full source indexes, and the next woke state (woke.ts). */
  wake: WakeDetection;
  /** Backtest inputs, present when the run refreshes the backtest (backtest.ts). */
  backtest?: BacktestInputs;
}

/** KEV CVE ids sharing one canonical vendor (or vendor + product), and how CISA spells it. */
export interface KevPriorEntry {
  /** Most frequent KEV spelling, e.g. "Juniper" or "Juniper Junos OS". */
  name: string;
  ids: Set<string>;
}

/** KEV prior keyed by canonical vendor ("juniper") and "vendor|product" ("juniper|junosos"). */
export interface KevPrior {
  vendors: Map<string, KevPriorEntry & { tokens: string[] }>;
  products: Map<string, KevPriorEntry>;
  /** First canonical token → token lists of the KEV vendors starting with it (prefix fallback). */
  prefixes: Map<string, string[][]>;
}

export interface Enrichment {
  kev: KevCatalog;
  epss: EpssTable;
  exploits: ExploitIndex;
  prior: KevPrior;
  /**
   * Sources with neither a live nor a cached copy this run (id → display name). Their silence is
   * not evidence: scoring emits unknown chips instead of "never in KEV" / "no exploit".
   */
  unavailable: ReadonlyMap<SourceId, string>;
}

export interface ScoredCve {
  cve: NormalizedCve;
  score: number;
  raw: number;
  /** Tier at the default knob. */
  tier: Tier;
  exploited: boolean;
  weaponized: boolean;
  reasons: Reason[];
  unknowns: string[];
  kev: KevInfo | null;
  epss: EpssInfo | null;
  exploits: ExploitEvidence;
  timeline: CveDetail['timeline'];
  /** Set by assignBatches(). */
  batch: string | null;
  /** Set by buildWoke() for old CVEs that woke up. */
  woke: WokeInfo | null;
}
