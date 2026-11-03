/**
 * Pipeline configuration: upstream URLs, licences, timeouts, sanity thresholds, the window size
 * and output budgets. Brand strings come from shared/brand.ts.
 */
import { BRAND, REPO_URL } from '../../shared/brand';
import type { SourceId } from '../../shared/contract';

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
} as const;

export const EXPLOITDB = {
  info: { id: 'exploitdb', name: 'Exploit-DB', home: 'https://www.exploit-db.com/', license: 'GPL-2.0 (only IDs, flags and links are republished)' } satisfies SourceInfo,
  urls: ['https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'],
  entryUrl: (id: string) => `https://www.exploit-db.com/exploits/${id}`,
  /** GitLab rate-limits raw downloads: reuse a cached copy younger than this. */
  minIntervalMs: 6 * 3_600_000,
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

/** Minimum upstream sizes; anything smaller is treated as a broken download. */
export interface SanityLimits {
  cvelistRecords: number;
  kevEntries: number;
  /** KEV only grows: reject a catalog below this fraction of the cached copy. */
  kevMinRatioOfCached: number;
  epssRows: number;
  metasploitModules: number;
  nucleiTemplates: number;
  exploitdbRows: number;
  pocFiles: number;
}

export const SANITY: SanityLimits = {
  cvelistRecords: 300_000,
  kevEntries: 1_000,
  kevMinRatioOfCached: 0.98,
  epssRows: 200_000,
  metasploitModules: 3_000,
  nucleiTemplates: 2_000,
  exploitdbRows: 40_000,
  pocFiles: 5_000,
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
    'v1/batches.json': 96 * 1024,
    'v1/kev.json': 32 * 1024,
    'v1/changes.json': 32 * 1024,
    'v1/woke.json': 64 * 1024,
    'v1/receipts.json': 64 * 1024,
    /**
     * Internal carry-forward state (state.ts): woke tracking (~25 KB) plus the Receipts forward log,
     * which grows to ~200,000 CVEs over its 400-day retention (~230 KB gzip in a realistic simulation).
     */
    'v1/state.json': 640 * 1024,
    'feeds/signal.xml': 64 * 1024,
    'feeds/kev.xml': 32 * 1024,
    'feeds/kev-due.ics': 32 * 1024,
    'feeds/woke.xml': 64 * 1024,
  },
  /** Each `v1/cve/<xx>.json` shard. */
  shardGzipBytes: 80 * 1024,
  maxFiles: 300,
} as const;
