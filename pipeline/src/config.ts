/**
 * Pipeline configuration: upstream URLs, licences, timeouts, sanity thresholds, the window size
 * and output budgets. Brand strings come from shared/brand.ts.
 */
import { BRAND, REPO_URL } from '../../shared/brand';
import type { PackageEcosystem, SourceId } from '../../shared/contract';

export const USER_AGENT = `${BRAND.slug}-pipeline (+${REPO_URL})`;

/** Days of CVE publications in the window by default. */
export const DEFAULT_WINDOW_DAYS = 30;

export const HTTP_TIMEOUT_MS = 60_000;
/** Delays before the 1st, 2nd and 3rd retry. */
export const HTTP_RETRY_DELAYS_MS: readonly number[] = [2_000, 4_000, 8_000];
export const GIT_TIMEOUT_MS = 20 * 60_000;

/** Static description of a source, copied into its SourceStatus. */
export interface SourceInfo {
  id: SourceId;
  name: string;
  /** Human-facing home of the data; used as the status URL when no download URL applies. */
  home: string;
  license: string;
}

export interface GitSourceConfig {
  info: SourceInfo;
  remote: string;
  branch: string;
  /** Clone directory under `<cache>/git/`. */
  cloneDir: string;
}

const CISA_TERMS = 'CC0-1.0 (no CISA/DHS endorsement implied)';

export const CVELIST: GitSourceConfig = {
  info: {
    id: 'cvelist',
    name: 'CVE List V5',
    home: 'https://github.com/CVEProject/cvelistV5',
    license: 'CVE Terms of Use (https://www.cve.org/Legal/TermsOfUse), © The MITRE Corporation',
  },
  remote: 'https://github.com/CVEProject/cvelistV5.git',
  branch: 'main',
  cloneDir: 'cvelistV5',
};

/** CISA's ADP container (Vulnrichment) arrives inside CVE List records. */
export const CISA_ADP = {
  info: { id: 'cisa-adp', name: 'CISA ADP (Vulnrichment)', home: 'https://github.com/cisagov/vulnrichment', license: CISA_TERMS } satisfies SourceInfo,
  /** `providerMetadata.shortName` of the container. */
  shortName: 'CISA-ADP',
} as const;

export const KEV = {
  info: { id: 'kev', name: 'CISA Known Exploited Vulnerabilities', home: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', license: CISA_TERMS } satisfies SourceInfo,
  urls: [
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
  ],
} as const;

export const EPSS = {
  info: {
    id: 'epss',
    name: 'EPSS (FIRST)',
    home: 'https://www.first.org/epss/',
    license: 'FIRST EPSS usage agreement: free use, attribution requested (https://www.first.org/epss)',
  } satisfies SourceInfo,
  current: 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
  /** Daily archive, tried for today and then yesterday (UTC). */
  daily: (ymd: string) => `https://raw.githubusercontent.com/empiricalsec/epss_scores/main/${ymd.slice(0, 4)}/epss_scores-${ymd}.csv.gz`,
  /** A past day on the EPSS host (fallback for the archive). */
  dated: (ymd: string) => `https://epss.empiricalsecurity.com/epss_scores-${ymd}.csv.gz`,
} as const;

export const METASPLOIT = {
  info: { id: 'metasploit', name: 'Metasploit Framework', home: 'https://github.com/rapid7/metasploit-framework', license: 'BSD-3-Clause' } satisfies SourceInfo,
  urls: ['https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json'],
  /** Module `path` values ("/modules/…") are relative to this. */
  blobBase: 'https://github.com/rapid7/metasploit-framework/blob/master',
} as const;

export const NUCLEI = {
  info: { id: 'nuclei', name: 'Nuclei templates', home: 'https://github.com/projectdiscovery/nuclei-templates', license: 'MIT' } satisfies SourceInfo,
  urls: ['https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json'],
  /** Template `file_path` values are relative to this. */
  blobBase: 'https://github.com/projectdiscovery/nuclei-templates/blob/main',
  /**
   * Template landing dates come from the repository's own history: a blobless clone (trees and
   * commits, no file contents) under `<cache>/git/<historyDir>`, walked along the first parents of
   * `branch`. The dates are kept in `<cache>/sources/<datesFile>` and updated from the last commit
   * walked, so a run with that file only fetches the commits since then.
   */
  remote: 'https://github.com/projectdiscovery/nuclei-templates.git',
  branch: 'main',
  historyDir: 'nuclei-templates',
  datesFile: 'nuclei-dates.json',
  commitBase: 'https://github.com/projectdiscovery/nuclei-templates/commit',
  /** Per git command. A cold clone and walk took about 15 s (2026-11-13). */
  gitTimeoutMs: 5 * 60_000,
  /**
   * With a dates file and no clone, clone only this many commits deep (about 180 first-parent
   * commits, two days of main, 35 MB, 5 s on 2026-11-13); the rest is fetched only when the last
   * walked commit is not in it. GitHub's --shallow-since cut this repository at about 25 commits
   * whatever the date, so it is not used.
   */
  shallowDepth: 100,
} as const;

export const EXPLOITDB = {
  info: { id: 'exploitdb', name: 'Exploit-DB', home: 'https://www.exploit-db.com/', license: 'GPL-2.0 (only IDs, flags and links are republished)' } satisfies SourceInfo,
  urls: ['https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'],
  entryUrl: (id: string) => `https://www.exploit-db.com/exploits/${id}`,
  /** GitLab rate-limits raw downloads: reuse a cached copy younger than this. */
  minIntervalMs: 6 * 3_600_000,
} as const;

/**
 * ENISA's EU Known Exploited Vulnerabilities, from the EUVD consolidated KEV dump (CISA KEV and EU
 * KEV in one list, refreshed daily at 07:00 UTC). Only entries whose `sources` include `eukev_kev`
 * are used. `dateAdded` is the earliest date across both sources, so it dates the EU listing only
 * for an EU-only entry, or when it is before the CVE's CISA date (sources/catalogs.ts).
 */
export const EU_KEV = {
  info: {
    id: 'eu-kev',
    name: 'ENISA EU KEV',
    home: 'https://euvd.enisa.europa.eu/',
    license: 'ENISA material: reproduction authorised, provided the source is acknowledged (https://www.enisa.europa.eu/about-enisa/legal-notice/legal-notice)',
  } satisfies SourceInfo,
  urls: ['https://euvdservices.enisa.europa.eu/api/kev/dump'],
  entryUrl: (euvdId: string) => `https://euvd.enisa.europa.eu/vulnerability/${euvdId}`,
  /** The dump changes once a day: reuse a copy younger than this without a request. */
  minIntervalMs: 6 * 3_600_000,
} as const;

/**
 * Sources whose reuse interval `--fresh` may skip (by cache key). Only EU KEV: the fast check
 * (scripts/fast-check.sh) dispatches a run when ENISA's dump changed, and that run must not reuse a
 * copy up to 6 h old. CIRCL's 12 h interval is its API's own policy and stays.
 */
export const FRESH_SOURCES: readonly string[] = ['eu-kev'];

/**
 * CIRCL Vulnerability-Lookup KEV catalogs (GCVE BCP-07 entries), one catalog per request through
 * the `vulnerability_lookup_origin` filter. Anonymous use is limited to 20 requests a minute and
 * the API policy asks not to mirror the dataset: two requests every 12 hours stay far below that.
 * Only catalogs whose licence CIRCL states are used (CISA's copy duplicates `kev`).
 */
const circlKevUrl = (origin: string) => `https://vulnerability.circl.lu/api/kev/?vulnerability_lookup_origin=${origin}&per_page=1000`;
const CIRCL_MIN_INTERVAL_MS = 12 * 3_600_000;

export const CIRCL_KEV = {
  info: {
    id: 'circl-kev',
    name: 'CIRCL known exploited catalog',
    home: 'https://vulnerability.circl.lu/known-exploited-vulnerabilities-catalog/?catalog_uuid=1a89b78e-f703-45f3-bb86-59eb712668bd',
    license: 'CC0-1.0 (CIRCL, via Vulnerability-Lookup)',
  } satisfies SourceInfo,
  origin: '1a89b78e-f703-45f3-bb86-59eb712668bd',
  urls: [circlKevUrl('1a89b78e-f703-45f3-bb86-59eb712668bd')],
  entryUrl: (cve: string) => `https://vulnerability.circl.lu/vuln/${cve.toLowerCase()}`,
  minIntervalMs: CIRCL_MIN_INTERVAL_MS,
} as const;

export const SIBERKAPAN = {
  info: {
    id: 'siberkapan',
    name: 'SiberKapan honeypot catalog',
    home: 'https://siberkapan.org/kev-catalog',
    license: 'CC-BY-4.0 (SiberKapan, via CIRCL Vulnerability-Lookup)',
  } satisfies SourceInfo,
  origin: 'fc16d4f5-594d-5807-9bf1-71af4407c589',
  urls: [circlKevUrl('fc16d4f5-594d-5807-9bf1-71af4407c589')],
  entryUrl: (cve: string) => `https://vulnerability.circl.lu/vuln/${cve.toLowerCase()}`,
  minIntervalMs: CIRCL_MIN_INTERVAL_MS,
} as const;

export const POC: GitSourceConfig = {
  info: {
    id: 'poc-github',
    name: 'PoC-in-GitHub',
    home: 'https://github.com/nomi-sec/PoC-in-GitHub',
    license: 'CC0-1.0 (listed repositories are third-party, unverified code)',
  },
  remote: 'https://github.com/nomi-sec/PoC-in-GitHub.git',
  branch: 'master',
  cloneDir: 'poc',
};

/**
 * OSV.dev advisories behind v1/packages.json (pipeline/src/sources/osv.ts). A compact mirror of
 * the eight ecosystems lives in `<cache>/sources/`; each run brings it up to date from the
 * `modified_id.csv` heads, and every 7 days from the full `all.zip` dumps. OSV never feeds a
 * score: it is in meta.sources for its health only (NON_SCORING_SOURCES in emit/build.ts).
 */
export interface OsvConfig {
  info: SourceInfo;
  base: string;
  isAllowedHost: (host: string) => boolean;
  mirrorFile: string;
  fullSyncMs: number;
  fullRetryMs: number;
  csvHeadBytes: number;
  csvMaxBytes: number;
  csvOverlapMs: number;
  maxChangedIds: number;
  concurrency: number;
  budgetMs: number;
  max404: number;
  limits: { zipBytes: number; zipTimeoutMs: number; zipRetryDelaysMs: readonly number[]; recordBytes: number };
  maxExtraVersions: number;
  maxRanges: number;
  maxEvents: number;
  maxNameLength: number;
}

export const OSV: OsvConfig = {
  info: {
    id: 'osv',
    name: 'OSV.dev advisories',
    home: 'https://osv.dev',
    license:
      "Each database's own: GitHub Advisory Database, PyPI Advisory Database and Go Vulnerability Database CC-BY-4.0, RustSec CC0-1.0, Drupal MIT (see packages.json attribution); only advisory IDs, package names and version ranges are kept",
  },
  /** The bucket as OSV.dev's data documentation names it: `<base>/<ecosystem>/all.zip`. */
  base: 'https://storage.googleapis.com/osv-vulnerabilities',
  /** Hosts a response may come from after redirects. */
  isAllowedHost: (host: string) => host === 'storage.googleapis.com' || host.endsWith('.storage.googleapis.com'),
  /** Cache file under `<cache>/sources/`. */
  mirrorFile: 'osv-mirror.json.gz',
  /** Re-read the full dump of an ecosystem this often. */
  fullSyncMs: 7 * 24 * 3_600_000,
  /** After a full dump fails (its download or its checks), wait this long before downloading it again (incremental runs meanwhile). */
  fullRetryMs: 24 * 3_600_000,
  /** First `modified_id.csv` range request; doubled until the cursor is reached, up to csvMaxBytes. */
  csvHeadBytes: 16 * 1024,
  csvMaxBytes: 1024 * 1024,
  /** Changes are re-read from this long before the cursor (re-applying a record is harmless). */
  csvOverlapMs: 2 * 3_600_000,
  /** More changed records than this in one run: read the full dump instead. */
  maxChangedIds: 2_000,
  /** Record downloads in flight, across all ecosystems. */
  concurrency: 8,
  /** The whole OSV step, all ecosystems; past it every ecosystem keeps its cached copy. */
  budgetMs: 5 * 60_000,
  /** This many 404s for changed records in one run look like an upstream fault: nothing is removed. */
  max404: 20,
  limits: {
    zipBytes: 1024 * 1024 * 1024,
    zipTimeoutMs: 240_000,
    /** Retries of an all.zip download (one). */
    zipRetryDelaysMs: [5_000],
    recordBytes: 1024 * 1024,
  },
  /** Per affected package of one advisory. */
  maxExtraVersions: 1_000,
  maxRanges: 64,
  maxEvents: 64,
  maxNameLength: 300,
};

/** Minimum upstream sizes; anything smaller is treated as a broken download. */
export interface SanityLimits {
  cvelistRecords: number;
  kevEntries: number;
  /** KEV only grows: reject a catalog below this fraction of the cached copy. */
  kevMinRatioOfCached: number;
  epssRows: number;
  metasploitModules: number;
  nucleiTemplates: number;
  /** CVEs with a template landing date after a full walk of the Nuclei history (4,678 on 2026-11-13). */
  nucleiDates: number;
  exploitdbRows: number;
  pocFiles: number;
  /** EU KEV entries in the EUVD dump (82 on 2026-11-18), and the dump's rows in all (1,799). */
  euKevEntries: number;
  euvdDumpRows: number;
  /** CVE entries in CIRCL's own catalog (33 on 2026-11-18) and in SiberKapan's (14). */
  circlKevEntries: number;
  siberkapanEntries: number;
  /**
   * OSV records kept (non-withdrawn, with a CVE alias and a package of the ecosystem) in a full
   * dump: about half of the 2026-11-03 counts. A dump below its floor, or below
   * osvMinRatioOfCached of the cached copy, is rejected and the cached copy kept.
   */
  osvRecords: Readonly<Record<PackageEcosystem, number>>;
  osvMinRatioOfCached: number;
}

export const SANITY: SanityLimits = {
  cvelistRecords: 300_000,
  kevEntries: 1_000,
  kevMinRatioOfCached: 0.98,
  epssRows: 200_000,
  metasploitModules: 3_000,
  nucleiTemplates: 2_000,
  nucleiDates: 2_000,
  exploitdbRows: 40_000,
  pocFiles: 5_000,
  euKevEntries: 40,
  euvdDumpRows: 1_000,
  circlKevEntries: 15,
  siberkapanEntries: 5,
  osvRecords: { npm: 3_000, PyPI: 6_500, Maven: 3_500, Go: 4_000, 'crates.io': 800, RubyGems: 500, Packagist: 3_000, NuGet: 500 },
  osvMinRatioOfCached: 0.9,
};

/** Gzip size budgets for emitted files (checked by validate.ts): warn at 80 %, fail at 150 %. */
export const BUDGETS = {
  warnRatio: 0.8,
  failRatio: 1.5,
  gzipBytes: {
    'v1/meta.json': 8 * 1024,
    'v1/signal.json': 120 * 1024,
    'v1/index.json': 1024 * 1024,
    'v1/stats.json': 80 * 1024,
    /** Measured 18 KB gzip on 2026-11-20 (30 CNAs, 1,774 KEV CVEs). Read only by The Surge. */
    'v1/surge.json': 48 * 1024,
    'v1/batches.json': 96 * 1024,
    'v1/kev.json': 32 * 1024,
    'v1/changes.json': 32 * 1024,
    /** Verdict events of 7 days (events.ts): an estimated 200 to 350 a week, 10 to 20 KB gzip. */
    'v1/events.json': 48 * 1024,
    'v1/woke.json': 64 * 1024,
    'v1/receipts.json': 64 * 1024,
    /** Measured 122 KB gzip on 2026-11-03 (1,365 CVEs, 807 packages). Raise it before splitting the file. */
    'v1/packages.json': 256 * 1024,
    /**
     * Internal carry-forward state (state.ts), read only by the pipeline: woke tracking (~25 KB)
     * plus the Receipts forward log. With times in minutes the log costs about 2.5 bytes gzip per
     * CVE: ~0.55 MB for the ~225,000 CVEs of 400 days at October 2026 volume (receipts.test.ts).
     */
    'v1/state.json': 1024 * 1024,
    'feeds/signal.xml': 64 * 1024,
    'feeds/kev.xml': 32 * 1024,
    'feeds/kev-due.ics': 32 * 1024,
    'feeds/woke.xml': 64 * 1024,
    'feeds/events.xml': 64 * 1024,
  },
  /** Each `v1/cve/<xx>.json` shard. */
  shardGzipBytes: 80 * 1024,
  maxFiles: 300,
} as const;
