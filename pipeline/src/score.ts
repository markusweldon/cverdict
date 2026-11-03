/**
 * Evidence scoring (docs/SPEC.md §2 "Scoring"): NormalizedCve + Enrichment → ScoredCve.
 *
 * Every weight comes from shared/model.ts. Thresholds that decide *whether* a chip fires
 * (EPSS bands, CVSS bands, PoC vetting) are part of the chip definitions and live here.
 * Within a family the strongest chip counts and the others are kept with 0 points, so the
 * site can show the full arithmetic: BASE_POINTS + Σ reason.points = score (before clamping).
 */
import {
  KNOB_DEFAULT,
  tierFor,
  type EpssInfo,
  type ExploitEvidence,
  type Family,
  type KevInfo,
  type Reason,
  type SourceId,
} from '../../shared/contract';
import {
  BASE_POINTS,
  CHIPS,
  COLD_START_DAYS,
  EXPLOITED_BONUS,
  EXPLOITED_FLOOR,
  RANSOMWARE_BONUS,
  chip,
} from '../../shared/model';
import type { Enrichment, KevCatalog, KevPrior, KevPriorEntry, KevRaw, NormalizedCve, PocRepo, ScoredCve } from './types';
import { DAY_MS, addDays, daysBetween, parseIsoDate, ymd } from './util/dates';

/** EPSS bands for epss.high / epss.mid; below EPSS_MID counts as "no exploit signal". */
const EPSS_HIGH = 0.1;
const EPSS_MID = 0.01;
/** CVSS bands for the SEV family. */
const CVSS_CRITICAL = 9.0;
const CVSS_HIGH = 7.0;
/** PoC vetting: a repo counts once it has this many stars or is this many days old. */
const POC_MIN_STARS = 2;
const POC_MIN_AGE_DAYS = 3;
/** More than HYPE_REPOS repos within HYPE_DAYS of the first one is attention, not weaponization. */
const HYPE_REPOS = 50;
const HYPE_DAYS = 7;
const POC_TOP = 5;

const TAG_DISPUTED = 'disputed';
const TAG_EOL = 'unsupported-when-assigned';
const HOBBY_RE = /sourcecodester|code-projects|itsourcecode|phpgurukul|campcodes|kashipara|projectworlds/i;
const WORDPRESS_CNAS = new Set(['wordfence', 'wpscan', 'patchstack']);
const WORDPRESS_RE = /wordpress (plugin|theme)|for wordpress/i;
const KERNEL_CNA = 'linux';

/**
 * v4 E:A means attacks are reported; v3 E:F / E:H mean working exploit code exists (weaponization,
 * not exploitation); E:P means a proof of concept. Only v4 uses A and only v3 uses F/H, so the
 * flat cnaExploitMaturity list is unambiguous.
 */
const VENDOR_EXPLOITED = ['A'];
const VENDOR_FUNCTIONAL = ['F', 'H'];
const VENDOR_POC = 'P';
/** Sources the X family reads; if one is unavailable, "no exploit" cannot be concluded. */
const X_SOURCES: readonly SourceId[] = ['metasploit', 'nuclei', 'exploitdb', 'poc-github', 'epss'];

const MSF_RANK_NAMES: Record<number, string> = {
  0: 'manual',
  100: 'low',
  200: 'average',
  300: 'normal',
  400: 'good',
  500: 'great',
  600: 'excellent',
};
const AV_NAMES: Record<string, string> = { N: 'network', A: 'adjacent', L: 'local', P: 'physical' };

// ── Labels and links ───────────────────────────────────────────────────────────────────────

const DAY_FMT = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
const DAY_YEAR_FMT = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
const INT_FMT = new Intl.NumberFormat('en-US');

/** UTC calendar day (YYYY-MM-DD) of a date or date-time string. */
export function utcDay(date: string): string {
  const d = parseIsoDate(date);
  return d ? ymd(d) : date.slice(0, 10);
}

/** "Oct 21". Accepts YYYY-MM-DD or ISO date-times. */
export function monthDay(date: string): string {
  const d = parseIsoDate(date);
  return d ? DAY_FMT.format(d) : date;
}

/** "Oct 21", or "Oct 21, 2024" when not in the current UTC year. */
export function dayLabel(date: string, now: Date): string {
  const d = parseIsoDate(date);
  if (!d) return date;
  return (d.getUTCFullYear() === now.getUTCFullYear() ? DAY_FMT : DAY_YEAR_FMT).format(d);
}

/** Thousands-separated integer, e.g. "1,407". */
export function formatInt(n: number): string {
  return INT_FMT.format(n);
}

/** Probability as a percentage with sensible precision: "14.2%", "3.1%", "0.43%", "0.043%". */
export function formatPercent(p: number): string {
  const pct = p * 100;
  return `${pct >= 1 ? pct.toFixed(1) : Number(pct.toPrecision(2)).toString()}%`;
}

function ordinal(n: number): string {
  const tens = n % 100;
  if (tens >= 11 && tens <= 13) return `${n}th`;
  return `${n}${['th', 'st', 'nd', 'rd'][n % 10] ?? 'th'}`;
}

function epssLabel(e: EpssInfo): string {
  return `EPSS ${formatPercent(e.score)} · ${ordinal(Math.floor(e.percentile * 100))} pct`;
}

function plural(n: number, word: string): string {
  return `${formatInt(n)} ${word}${n === 1 ? '' : 's'}`;
}

const cveOrgUrl = (id: string) => `https://www.cve.org/CVERecord?id=${id}`;
export const kevSearchUrl = (q: string) =>
  `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(q)}`;
export const epssUrl = (id: string) => `https://api.first.org/data/v1/epss?cve=${id}`;
export const pocIndexUrl = (id: string) => `https://github.com/nomi-sec/PoC-in-GitHub/blob/master/${id.split('-')[1]}/${id}.json`;

// ── Reasons ────────────────────────────────────────────────────────────────────────────────

interface ChipOverrides {
  points?: number;
  source?: SourceId;
  url?: string;
  at?: string;
}

/** A chip instance: catalogue metadata from shared/model.ts plus a specific label. */
function reason(id: string, label: string, o: ChipOverrides = {}): Reason {
  const def = chip(id);
  const r: Reason = {
    id,
    label,
    polarity: def.polarity,
    family: def.family,
    points: o.points ?? def.points,
    source: o.source ?? def.source,
  };
  if (o.url) r.url = o.url;
  if (o.at) r.at = o.at;
  return r;
}

interface FamilyResult {
  /** Winner first (full points), then the losers with points 0. */
  chips: Reason[];
  points: number;
}

/** Keep the strongest candidate (ties go to the earlier one); zero the rest. */
function strongest(candidates: Reason[], direction: 'max' | 'min'): FamilyResult {
  if (candidates.length === 0) return { chips: [], points: 0 };
  const sign = direction === 'max' ? -1 : 1;
  const ordered = candidates
    .map((r, i) => ({ r, i }))
    .sort((a, b) => sign * (a.r.points - b.r.points) || a.i - b.i)
    .map(({ r }) => r);
  const [winner, ...losers] = ordered;
  return { chips: [winner, ...losers.map((r) => ({ ...r, points: 0 }))], points: winner.points };
}

const FAMILY_ORDER: readonly Family[] = ['E', 'X', 'SEV', 'SSVC', 'PRIOR', 'NOISE', 'INFO'];
const CATALOGUE_INDEX = new Map(CHIPS.map((d, i) => [d.id, i]));

function sectionRank(r: Reason): number {
  if (r.polarity === 'unknown') return FAMILY_ORDER.length * CHIPS.length;
  const family = FAMILY_ORDER.indexOf(r.family) * CHIPS.length;
  return r.family === 'INFO' ? family + (CATALOGUE_INDEX.get(r.id) ?? 0) : family;
}

/**
 * Order chips as the contract requires: E, X, SEV, SSVC, PRIOR, NOISE, then INFO (catalogue
 * order), then unknowns. Stable, so the winner-first order inside each family is preserved.
 */
export function orderReasons(reasons: Reason[]): Reason[] {
  return reasons
    .map((r, i) => ({ r, i, k: sectionRank(r) }))
    .sort((a, b) => a.k - b.k || a.i - b.i)
    .map(({ r }) => r);
}

// ── KEV prior ──────────────────────────────────────────────────────────────────────────────

/** Trailing tokens naming a legal form or line of business, not the vendor: "QNAP Systems Inc." → qnap. */
const VENDOR_SUFFIXES = new Set([
  'corporation', 'corp', 'inc', 'incorporated', 'ltd', 'limited', 'llc', 'co', 'company', 'gmbh', 'ag', 'sa', 'plc', 'kk',
  'systems', 'networks', 'software', 'foundation', 'technologies', 'technology', 'mobile', 'cloud', 'labs', 'group',
]);
/** Renames and alternative names (canonical key → canonical key), for both KEV and CNA spellings. */
const VENDOR_ALIASES: Readonly<Record<string, string>> = {
  zimbra: 'synacor',
  netscaler: 'citrix',
  zohocorp: 'zoho',
  manageengine: 'zoho',
  hewlettpackardenterprise: 'hpe',
  hewlettpackard: 'hp',
};

/** Lower-cased, accent-free alphanumeric words; runs of single letters ("K.K.", "S.A.") become one word. */
function nameTokens(s: string): string[] {
  const words = s.normalize('NFKD').replace(/\p{M}+/gu, '').toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  const out: string[] = [];
  let letters = '';
  for (const w of words) {
    if (w.length === 1) {
      letters += w;
      continue;
    }
    if (letters) out.push(letters);
    letters = '';
    out.push(w);
  }
  if (letters) out.push(letters);
  return out;
}

/**
 * Canonical vendor tokens, so CNA legal names meet CISA's short names: "Juniper Networks" →
 * [juniper], "The Apache Software Foundation" → [apache], "Hewlett Packard Enterprise (HPE)" → [hpe].
 */
export function vendorTokens(name: string): string[] {
  let tokens = nameTokens(name.replace(/\([^)]*\)/g, ' '));
  if (tokens.length === 0) tokens = nameTokens(name);
  if (tokens.length > 1 && tokens[0] === 'the') tokens = tokens.slice(1);
  while (tokens.length > 1 && VENDOR_SUFFIXES.has(tokens[tokens.length - 1])) tokens = tokens.slice(0, -1);
  const alias = VENDOR_ALIASES[tokens.join('')];
  return alias ? [alias] : tokens;
}

/** Product key under a canonical vendor; a leading vendor name is dropped ("Apache Tomcat" → tomcat). */
function productKey(product: string, vendor: readonly string[]): string {
  const tokens = nameTokens(product);
  const prefixed = tokens.length > vendor.length && vendor.every((t, i) => tokens[i] === t);
  return (prefixed ? tokens.slice(vendor.length) : tokens).join('');
}

/**
 * The KEV vendor a name refers to: the same canonical tokens, else the longest KEV vendor whose
 * tokens start this name's tokens ("Siemens Mobility" → siemens). Whole tokens only, so "Applied
 * Signal" never matches "Apple".
 */
export function kevVendorKey(tokens: readonly string[], prior: KevPrior): string | null {
  const exact = tokens.join('');
  if (prior.vendors.has(exact)) return exact;
  if (EXACT_ONLY_VENDORS.has(tokens[0])) return null;
  let best: readonly string[] | null = null;
  for (const cand of prior.prefixes.get(tokens[0]) ?? []) {
    if (cand.length < tokens.length && cand.every((t, i) => tokens[i] === t) && cand.length > (best?.length ?? 0)) best = cand;
  }
  return best ? best.join('') : null;
}

/**
 * KEV vendors whose name is a common first word of unrelated vendors ("Linux Mint", "Progress
 * Planner"), so they only match exactly.
 */
const EXACT_ONLY_VENDORS = new Set(['linux', 'progress']);

export function buildKevPrior(kev: KevCatalog): KevPrior {
  type Acc = { ids: Set<string>; spellings: Map<string, number>; tokens: string[] };
  const vendorAcc = new Map<string, Acc>();
  const productAcc = new Map<string, Acc>();
  const add = (map: Map<string, Acc>, key: string, spelling: string, id: string, tokens: string[]) => {
    let acc = map.get(key);
    if (!acc) map.set(key, (acc = { ids: new Set(), spellings: new Map(), tokens }));
    acc.ids.add(id);
    acc.spellings.set(spelling, (acc.spellings.get(spelling) ?? 0) + 1);
  };
  for (const e of kev.entries.values()) {
    const tokens = vendorTokens(e.vendorProject);
    if (tokens.length === 0) continue;
    const v = tokens.join('');
    const vendorName = e.vendorProject.trim();
    const productName = e.product.trim();
    add(vendorAcc, v, vendorName, e.cveID, tokens);
    const p = productKey(productName, tokens);
    // "n8n" + "n8n" reads "n8n"; "Apache" + "Apache Tomcat" reads "Apache Tomcat".
    const named = productName.toLowerCase().startsWith(vendorName.toLowerCase()) ? productName : `${vendorName} ${productName}`;
    if (p) add(productAcc, `${v}|${p}`, named, e.cveID, tokens);
  }
  // The most frequent spelling names the entry (first seen on ties).
  const finish = (acc: Acc): KevPriorEntry => ({
    name: [...acc.spellings].reduce((a, b) => (b[1] > a[1] ? b : a))[0],
    ids: acc.ids,
  });
  const prefixes = new Map<string, string[][]>();
  for (const { tokens } of vendorAcc.values()) {
    const list = prefixes.get(tokens[0]);
    if (list) list.push(tokens);
    else prefixes.set(tokens[0], [tokens]);
  }
  return {
    vendors: new Map([...vendorAcc].map(([k, acc]) => [k, { ...finish(acc), tokens: acc.tokens }])),
    products: new Map([...productAcc].map(([k, acc]) => [k, finish(acc)])),
    prefixes,
  };
}

/** Size of a prior set, not counting the CVE being scored. */
function othersIn(set: Set<string> | undefined, self: string): number {
  if (!set) return 0;
  return set.size - (set.has(self) ? 1 : 0);
}

// ── Evidence assembly ──────────────────────────────────────────────────────────────────────

function kevInfo(k: KevRaw): KevInfo {
  const triage = k.forensicTriage?.trim().toLowerCase();
  return {
    date_added: k.dateAdded,
    due_date: k.dueDate,
    ransomware: k.knownRansomwareCampaignUse,
    forensic_triage: triage === 'yes' ? true : triage === 'no' ? false : null,
    name: k.vulnerabilityName,
    required_action: k.requiredAction,
    notes: k.notes,
  };
}

export interface PocSummary {
  evidence: ExploitEvidence['poc'];
  /** created_at of the oldest non-fork repo. */
  firstCreated: string | null;
  /** created_at of the oldest vetted repo. */
  firstVetted: string | null;
}

/** The PoC vetting rule (docs/SCORING.md): at least POC_MIN_STARS stars, or POC_MIN_AGE_DAYS old. */
export function isVettedPoc(r: PocRepo, now: Date): boolean {
  return r.stars >= POC_MIN_STARS || now.getTime() - Date.parse(r.created) >= POC_MIN_AGE_DAYS * DAY_MS;
}

export function summarisePoc(repos: PocRepo[], now: Date): PocSummary {
  const own = repos.filter((r) => !r.fork && Number.isFinite(Date.parse(r.created)));
  const byCreated = [...own].sort((a, b) => Date.parse(a.created) - Date.parse(b.created));
  const vetted = byCreated.filter((r) => isVettedPoc(r, now));
  const first = byCreated[0];
  const hypeUntil = first ? Date.parse(first.created) + HYPE_DAYS * DAY_MS : 0;
  const top = [...own]
    .sort((a, b) => b.stars - a.stars || Date.parse(a.created) - Date.parse(b.created))
    .slice(0, POC_TOP)
    .map((r) => ({ url: r.url, stars: r.stars, created: r.created }));
  return {
    evidence: {
      count: own.length,
      vetted: vetted.length,
      hype: byCreated.filter((r) => Date.parse(r.created) <= hypeUntil).length > HYPE_REPOS,
      top,
    },
    firstCreated: first?.created ?? null,
    firstVetted: vetted[0]?.created ?? null,
  };
}

/** Everything known about one CVE before chips are decided. */
interface Facts {
  cve: NormalizedCve;
  now: Date;
  /** Days since publication (fractional). */
  age: number;
  /** Whole days since publication, for labels. */
  day: number;
  cold: boolean;
  kevRaw: KevRaw | null;
  kev: KevInfo | null;
  epss: EpssInfo | null;
  exploits: ExploitEvidence;
  poc: PocSummary;
  /** Unavailable sources (id → name). */
  unavailable: ReadonlyMap<SourceId, string>;
}

function gatherFacts(cve: NormalizedCve, enr: Enrichment, now: Date): Facts {
  const age = daysBetween(parseIsoDate(cve.published) ?? now, now);
  const kevRaw = enr.kev.entries.get(cve.id) ?? null;
  const e = enr.epss.scores.get(cve.id);
  const epss: EpssInfo | null = e
    ? { score: e.epss, percentile: e.percentile, date: enr.epss.scoreDate ?? '', model: enr.epss.model ?? '' }
    : null;
  const poc = summarisePoc(enr.exploits.poc.get(cve.id) ?? [], now);
  return {
    cve,
    now,
    age,
    day: Math.max(0, Math.floor(age)),
    cold: age < COLD_START_DAYS,
    kevRaw,
    kev: kevRaw ? kevInfo(kevRaw) : null,
    epss,
    exploits: {
      metasploit: [...(enr.exploits.metasploit.get(cve.id) ?? [])],
      nuclei: [...(enr.exploits.nuclei.get(cve.id) ?? [])],
      exploitdb: [...(enr.exploits.exploitdb.get(cve.id) ?? [])],
      poc: poc.evidence,
    },
    poc,
    unavailable: enr.unavailable,
  };
}

// ── Families ───────────────────────────────────────────────────────────────────────────────

/** E — confirmed exploitation. Points are filled in once the raw score is known. */
function exploitationCandidates(f: Facts): Reason[] {
  const { cve, now } = f;
  const out: Reason[] = [];
  if (f.kevRaw) {
    out.push(
      reason('kev.listed', `CISA KEV · added ${dayLabel(f.kevRaw.dateAdded, now)} · due ${dayLabel(f.kevRaw.dueDate, now)}`, {
        url: kevSearchUrl(cve.id),
        at: f.kevRaw.dateAdded,
      }),
    );
  } else if (cve.adpKev) {
    const added = cve.adpKev.dateAdded;
    out.push(
      reason('kev.listed', added ? `CISA KEV · added ${dayLabel(added, now)} (per CVE record)` : 'CISA KEV (per CVE record)', {
        source: 'cisa-adp',
        url: cve.adpKev.reference ?? kevSearchUrl(cve.id),
        at: added ?? undefined,
      }),
    );
  }
  if (cve.ssvc?.exploitation === 'active') {
    const at = cve.ssvc.timestamp ?? undefined;
    out.push(
      reason('ssvc.active', `CISA SSVC: exploitation active${at ? ` · ${dayLabel(at, now)}` : ''}`, { url: cveOrgUrl(cve.id), at }),
    );
  }
  const exploitedE = cve.cnaExploitMaturity.filter((e) => VENDOR_EXPLOITED.includes(e));
  if (exploitedE.length > 0) {
    out.push(
      reason('vendor.exploited', `Vendor CVSS: exploitation reported (${unique(exploitedE).map((e) => `E:${e}`).join(', ')})`, {
        url: cveOrgUrl(cve.id),
      }),
    );
  }
  if (cve.vendorInTheWild) {
    out.push(
      reason('vendor.itw', `${cve.cna || 'CNA'} says exploited in the wild · ${dayLabel(cve.published, now)}`, {
        url: cveOrgUrl(cve.id),
        at: cve.published,
      }),
    );
  }
  return out;
}

/**
 * X — exploit artifacts and prediction. `pending` means the absence of an exploit is not
 * settled (an unvetted PoC exists, or an exploit feed is unavailable), so NOISE must not apply.
 */
function exploitFamily(f: Facts): { result: FamilyResult; info: Reason[]; pending: boolean } {
  const { cve, now, exploits, epss } = f;
  const cands: Reason[] = [];
  const info: Reason[] = [];
  const more = (n: number) => (n > 1 ? ` +${n - 1} more` : '');

  if (exploits.metasploit.length > 0) {
    const best = [...exploits.metasploit].sort(
      (a, b) => Number(b.type === 'exploit') - Number(a.type === 'exploit') || (b.rank ?? -1) - (a.rank ?? -1),
    )[0];
    const rank = best.rank === null ? '' : ` (${MSF_RANK_NAMES[best.rank] ?? `rank ${best.rank}`})`;
    cands.push(reason('x.metasploit', `Metasploit: ${best.fullname}${rank}${more(exploits.metasploit.length)}`, { url: best.url }));
  }
  if (exploits.nuclei.length > 0) {
    const best = exploits.nuclei[0];
    const protocol = best.path.split('/')[0];
    const detail = [protocol, best.severity].filter(Boolean).join(' · ');
    cands.push(
      reason('x.nuclei', `Nuclei template${detail ? ` (${detail})` : ''}: scannable at scale${more(exploits.nuclei.length)}`, {
        url: best.url,
      }),
    );
  }
  if (exploits.exploitdb.length > 0) {
    const best = [...exploits.exploitdb].sort(
      (a, b) => Number(b.verified) - Number(a.verified) || (a.date ?? '9999').localeCompare(b.date ?? '9999'),
    )[0];
    const date = best.date ? ` · ${dayLabel(best.date, now)}` : '';
    cands.push(
      reason('x.exploitdb', `Exploit-DB ${best.id}${best.verified ? ' (verified)' : ''}${date}${more(exploits.exploitdb.length)}`, {
        url: best.url,
        at: best.date ?? undefined,
      }),
    );
  }
  if (epss && !f.cold && epss.score >= EPSS_HIGH) {
    cands.push(reason('epss.high', epssLabel(epss), { url: epssUrl(cve.id), at: epss.date || undefined }));
  }
  const poc = exploits.poc;
  if (poc.vetted > 0) {
    cands.push(
      reason('x.poc', `${plural(poc.count, 'PoC repo')} (${formatInt(poc.vetted)} vetted) — unverified, may be malware`, {
        url: pocIndexUrl(cve.id),
        at: f.poc.firstVetted ?? undefined,
      }),
    );
  } else if (poc.count > 0) {
    info.push(
      reason('poc.unvetted', `${plural(poc.count, 'new PoC repo')}, unstarred and < ${POC_MIN_AGE_DAYS} days old — not counted yet`, {
        url: pocIndexUrl(cve.id),
        at: f.poc.firstCreated ?? undefined,
      }),
    );
  }
  if (poc.hype) {
    info.push(
      reason('poc.hype', `PoC hype: > ${HYPE_REPOS} repos within ${HYPE_DAYS} days — attention, not weaponization`, {
        url: pocIndexUrl(cve.id),
        at: f.poc.firstCreated ?? undefined,
      }),
    );
  }
  if (cve.ssvc?.exploitation === 'poc') {
    const at = cve.ssvc.timestamp ?? undefined;
    cands.push(reason('ssvc.poc', `CISA SSVC: public PoC${at ? ` · ${dayLabel(at, now)}` : ''}`, { url: cveOrgUrl(cve.id), at }));
  }
  const functional = cve.cnaExploitMaturity.filter((e) => VENDOR_FUNCTIONAL.includes(e));
  if (functional.length > 0) {
    cands.push(
      reason('vendor.functional', `Vendor CVSS: working exploit code exists (${unique(functional).map((e) => `E:${e}`).join(', ')})`, {
        url: cveOrgUrl(cve.id),
      }),
    );
  }
  if (cve.cnaExploitMaturity.includes(VENDOR_POC)) {
    cands.push(reason('vendor.poc', 'Vendor CVSS: proof of concept exists (E:P)', { url: cveOrgUrl(cve.id) }));
  }
  if (epss && !f.cold && epss.score >= EPSS_MID && epss.score < EPSS_HIGH) {
    cands.push(reason('epss.mid', epssLabel(epss), { url: epssUrl(cve.id), at: epss.date || undefined }));
  }
  if (epss && f.cold) {
    info.push(
      reason('epss.cold', `${epssLabel(epss)} · day ${f.day} — too new to trust`, { url: epssUrl(cve.id), at: epss.date || undefined }),
    );
  }

  const down = X_SOURCES.flatMap((id) => f.unavailable.get(id) ?? []);
  const unvetted = poc.count - poc.vetted;
  const pending = down.length > 0 || unvetted > 0;
  if (cands.length > 0) return { result: strongest(cands, 'max'), info, pending };
  const unknown = (label: string) => ({ result: { chips: [reason('x.too_new', label)], points: 0 }, info, pending });
  if (f.cold) return unknown(`Too new: day ${f.day} of ${COLD_START_DAYS} — exploit feeds lag`);
  // Nothing fired after the cold start: (weak) evidence of absence, unless part of the evidence is missing.
  if (down.length > 0) return unknown(`Exploit check incomplete: ${down.join(', ')} unavailable this run`);
  if (unvetted > 0) return unknown(`Not settled: ${plural(unvetted, 'PoC repo')} too new to vet`);
  const epssText = epss ? `EPSS ${formatPercent(epss.score)}` : 'no EPSS score';
  const none = reason('x.none', `No public exploit after ${f.day} days · ${epssText}`);
  return { result: { chips: [none], points: none.points }, info, pending };
}

function severityFamily(f: Facts): { result: FamilyResult; info: Reason[] } {
  const { cvss, cvssMetrics } = f.cve;
  if (!cvss || cvss.version === '2.0') {
    const label = cvss ? `Only CVSS v2 (${cvss.score.toFixed(1)}), not scored` : 'No CVSS from the CNA or CISA-ADP';
    return { result: { chips: [reason('sev.none', label)], points: 0 }, info: [] };
  }
  const source: SourceId = cvss.source === 'cisa-adp' ? 'cisa-adp' : 'cvelist';
  const s = cvss.score;
  const score = s.toFixed(1);
  const av = AV_NAMES[cvssMetrics.AV] ?? 'unknown vector';
  const version = ` (v${cvss.version})`;
  let r: Reason;
  if (s >= CVSS_CRITICAL && cvssMetrics.AV === 'N') r = reason('sev.crit_net', `Critical ${score} · network${version}`, { source });
  else if (s >= CVSS_CRITICAL) r = reason('sev.crit', `Critical ${score} · ${av}${version}`, { source });
  else if (s >= CVSS_HIGH) r = reason('sev.high', `High ${score} · ${av}${version}`, { source });
  else r = reason('sev.low', `${s >= 4 ? 'Medium' : s > 0 ? 'Low' : 'None'} ${score} · ${av}${version}`, { source });
  const info = cvss.source === 'cisa-adp' ? [reason('sev.adp', `No CNA score; CISA-ADP CVSS ${score} used`)] : [];
  return { result: { chips: [r], points: r.points }, info };
}

function ssvcFamily(f: Facts): FamilyResult {
  const { ssvc } = f.cve;
  if (!ssvc) return { chips: [reason('ssvc.missing', 'No CISA SSVC assessment yet')], points: 0 };
  const at = ssvc.timestamp ?? undefined;
  const url = cveOrgUrl(f.cve.id);
  const chips: Reason[] = [];
  if (ssvc.automatable === 'yes') chips.push(reason('ssvc.automatable', 'CISA SSVC: automatable', { at, url }));
  else if (ssvc.automatable === 'no') chips.push(reason('ssvc.not_automatable', 'CISA SSVC: not automatable', { at, url }));
  if (ssvc.technical_impact === 'total') chips.push(reason('ssvc.total', 'CISA SSVC: total technical impact', { at, url }));
  else if (ssvc.technical_impact === 'partial') chips.push(reason('ssvc.partial', 'CISA SSVC: partial technical impact', { at, url }));
  // The two decision points are independent and add; show the stronger one first.
  chips.sort((a, b) => b.points - a.points);
  return { chips, points: chips.reduce((sum, r) => sum + r.points, 0) };
}

/** PRIOR — prior.unknown when the KEV catalog is unavailable or no vendor is named. */
function priorFamily(f: Facts, prior: KevPrior): { result: FamilyResult; vendorNamed: boolean } {
  const { cve } = f;
  const pairs = cve.affected.map((a) => ({ vendor: a.vendor, product: a.product }));
  if (f.kevRaw) pairs.push({ vendor: f.kevRaw.vendorProject, product: f.kevRaw.product });

  let product: { count: number; entry?: KevPriorEntry } = { count: 0 };
  let vendor: { count: number; entry?: KevPriorEntry } = { count: 0 };
  let firstVendor = '';
  for (const pair of pairs) {
    const tokens = vendorTokens(pair.vendor);
    if (tokens.length === 0) continue;
    firstVendor ||= pair.vendor;
    const key = kevVendorKey(tokens, prior);
    if (!key) continue;
    const v = prior.vendors.get(key)!;
    const vc = othersIn(v.ids, cve.id);
    if (vc > vendor.count) vendor = { count: vc, entry: v };
    const p = productKey(pair.product, v.tokens);
    const pe = p ? prior.products.get(`${key}|${p}`) : undefined;
    const pc = othersIn(pe?.ids, cve.id);
    if (pc > product.count) product = { count: pc, entry: pe };
  }

  let r: Reason;
  const kevDown = f.unavailable.get('kev');
  if (kevDown) r = reason('prior.unknown', `${kevDown} unavailable this run — KEV history not checked`);
  else if (!firstVendor) r = reason('prior.unknown', 'No affected vendor named — KEV history not checked');
  else if (product.entry) {
    const { name } = product.entry;
    r = reason('prior.product', `Product in KEV (×${formatInt(product.count)}): ${name}`, { url: kevSearchUrl(name) });
  } else if (vendor.entry) {
    const { name } = vendor.entry;
    r = reason('prior.vendor', `Vendor in KEV (×${formatInt(vendor.count)}): ${name}`, { url: kevSearchUrl(name) });
  } else {
    r = reason('prior.none', `Never in KEV: ${firstVendor}`);
  }
  return { result: { chips: [r], points: r.points }, vendorNamed: firstVendor !== '' };
}

/** NOISE candidates; applied only when there is no exploitation and the X family settled on ≤ 0. */
function noiseCandidates(f: Facts): Reason[] {
  const { cve } = f;
  const cna = cve.cna.toLowerCase();
  const out: Reason[] = [];
  const hobby = HOBBY_RE.exec(cve.noiseText);
  if (hobby) out.push(reason('noise.hobby', `Tutorial/hobby project (${hobby[0].toLowerCase()})`));
  if (cve.tags.includes(TAG_DISPUTED)) out.push(reason('noise.disputed', 'Disputed by the vendor or others'));
  if (WORDPRESS_CNAS.has(cna) || WORDPRESS_RE.test(cve.noiseText)) {
    out.push(reason('noise.wordpress', WORDPRESS_CNAS.has(cna) ? `WordPress plugin/theme (via ${cve.cna})` : 'WordPress plugin/theme'));
  }
  if (cna === KERNEL_CNA && cve.ssvc?.technical_impact !== 'total') {
    out.push(reason('noise.kernel', 'Linux kernel bug-fix CVE (impact not total)'));
  }
  return out;
}

function kevInfoChips(f: Facts): Reason[] {
  const k = f.kevRaw;
  if (!k) return [];
  const out: Reason[] = [];
  const due = parseIsoDate(k.dueDate);
  if (due) {
    const days = Math.round((due.getTime() - Date.parse(ymd(f.now))) / DAY_MS);
    const when = days > 0 ? `in ${plural(days, 'day')}` : days === 0 ? 'today' : `${plural(-days, 'day')} ago`;
    out.push(reason('kev.due', `KEV due ${dayLabel(k.dueDate, f.now)} · ${when}`, { url: kevSearchUrl(f.cve.id), at: k.dueDate }));
  }
  if (f.kev?.forensic_triage) {
    out.push(reason('kev.forensic', 'CISA asks for forensic triage (BOD 26-04)', { url: kevSearchUrl(f.cve.id), at: k.dateAdded }));
  }
  return out;
}

function cveInfoChips(f: Facts): Reason[] {
  const { cve } = f;
  const out: Reason[] = [];
  if (cve.aiCredit) out.push(reason('ai.credit', `AI-credited: “${cve.aiCredit}”`, { url: cveOrgUrl(cve.id) }));
  if (cve.tags.includes(TAG_EOL)) out.push(reason('tag.eol', 'Unsupported when assigned: replace or mitigate', { url: cveOrgUrl(cve.id) }));
  return out;
}

/** "A", "A and B", "A, B and C". */
function listing(names: readonly string[]): string {
  return names.length < 2 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

function unknownsFor(f: Facts, vendorNamed: boolean): string[] {
  const { cve } = f;
  const out: string[] = [];
  if (!cve.cvss) out.push('No CVSS score from the CNA or CISA-ADP.');
  else if (cve.cvss.version === '2.0') out.push('Only a CVSS v2 score exists, which is not used for scoring.');
  if (!cve.ssvc) out.push('No CISA SSVC assessment yet (exploitation, automatable, technical impact).');
  if (!f.epss && !f.unavailable.has('epss')) out.push('No EPSS score yet.');
  else if (f.epss && f.cold) out.push(`EPSS is not trusted until day ${COLD_START_DAYS}; this CVE is on day ${f.day}.`);
  if (f.cold) out.push(`Exploit feeds have not caught up yet (day ${f.day} of ${COLD_START_DAYS}).`);
  const { poc } = f.exploits;
  if (poc.count > 0 && poc.vetted === 0) {
    out.push(`A PoC repo appeared but is not vetted yet: it counts once it is ${POC_MIN_AGE_DAYS} days old or has ${POC_MIN_STARS} stars.`);
  }
  if (!vendorNamed) out.push('No affected vendor is named, so KEV history could not be checked.');
  const down = [...f.unavailable.values()];
  if (down.length > 0) {
    out.push(`${listing(down)} could not be loaded this run, so ${down.length === 1 ? 'its' : 'their'} evidence is unknown, not counted as absent.`);
  }
  return out;
}

function timelineFor(f: Facts): ScoredCve['timeline'] {
  const { cve, now } = f;
  const events: (ScoredCve['timeline'][number] & { t: number })[] = [];
  const add = (at: string | null | undefined, event: string, source: SourceId) => {
    const t = at ? parseIsoDate(at)?.getTime() : undefined;
    if (at && t !== undefined) events.push({ at, event, source, t });
  };
  add(cve.reserved, 'CVE ID reserved', 'cvelist');
  add(cve.published, `Published by ${cve.cna || 'the CNA'}`, 'cvelist');
  if (cve.ssvc) add(cve.ssvc.timestamp, `CISA SSVC assessment: exploitation ${cve.ssvc.exploitation || 'unknown'}`, 'cisa-adp');
  if (f.epss) add(f.epss.date, `EPSS scored ${formatPercent(f.epss.score)}`, 'epss');
  add(f.poc.firstCreated, 'First PoC repo created on GitHub', 'poc-github');
  const edb = f.exploits.exploitdb.filter((e) => e.date).sort((a, b) => (a.date ?? '').localeCompare(b.date ?? ''))[0];
  if (edb) add(edb.date, `Exploit-DB ${edb.id} published`, 'exploitdb');
  if (f.kevRaw) {
    add(f.kevRaw.dateAdded, 'Added to CISA KEV', 'kev');
    const due = parseIsoDate(f.kevRaw.dueDate);
    if (due && addDays(due, 1) > now) add(f.kevRaw.dueDate, 'CISA KEV remediation due', 'kev');
  } else if (cve.adpKev) {
    add(cve.adpKev.dateAdded, 'Added to CISA KEV (per CVE record)', 'cisa-adp');
  }
  return events
    .map((e, i) => ({ e, i }))
    .sort((a, b) => a.e.t - b.e.t || a.i - b.i)
    .map(({ e: { at, event, source } }) => ({ at, event, source }));
}

function unique<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}

// ── Score ──────────────────────────────────────────────────────────────────────────────────

export function scoreCve(cve: NormalizedCve, enr: Enrichment, opts: { now: Date; knob?: number }): ScoredCve {
  const f = gatherFacts(cve, enr, opts.now);

  const eCands = exploitationCandidates(f);
  const exploited = eCands.length > 0;
  const x = exploitFamily(f);
  const sev = severityFamily(f);
  const ssvc = ssvcFamily(f);
  const prior = priorFamily(f, enr.prior);
  const noiseCands = noiseCandidates(f);
  const noiseApplies = !exploited && x.result.points <= 0 && !x.pending;
  const noise = noiseApplies ? strongest(noiseCands, 'min') : { chips: noiseCands.map((r) => ({ ...r, points: 0 })), points: 0 };

  const raw = BASE_POINTS + x.result.points + sev.result.points + ssvc.points + prior.result.points + noise.points;

  let score: number;
  const eChips: Reason[] = [];
  if (exploited) {
    // The winning E chip carries the bonus and the floor (and the 100 cap), so the chips
    // still add up to the score; the other E chips are shown with 0.
    const floored = Math.min(100, Math.max(raw + EXPLOITED_BONUS, EXPLOITED_FLOOR));
    const ransomware = f.kevRaw?.knownRansomwareCampaignUse.trim().toLowerCase() === 'known';
    score = ransomware ? Math.min(100, floored + RANSOMWARE_BONUS) : floored;
    const [winner, ...losers] = eCands;
    eChips.push({ ...winner, points: floored - raw });
    if (ransomware) {
      eChips.push(
        reason('kev.ransomware', 'CISA KEV: known ransomware use', { points: score - floored, url: kevSearchUrl(cve.id), at: f.kevRaw?.dateAdded }),
      );
    }
    eChips.push(...losers.map((r) => ({ ...r, points: 0 })));
  } else {
    score = Math.min(100, Math.max(0, raw));
  }

  const weaponized = f.exploits.metasploit.length > 0 || f.exploits.nuclei.length > 0;
  const reasons = orderReasons([
    ...eChips,
    ...x.result.chips,
    ...sev.result.chips,
    ...ssvc.chips,
    ...prior.result.chips,
    ...noise.chips,
    ...kevInfoChips(f),
    ...cveInfoChips(f),
    ...sev.info,
    ...x.info,
  ]);

  return {
    cve,
    score,
    raw,
    tier: tierFor(score, exploited, weaponized, opts.knob ?? KNOB_DEFAULT),
    exploited,
    weaponized,
    reasons,
    unknowns: unknownsFor(f, prior.vendorNamed),
    kev: f.kev,
    epss: f.epss,
    exploits: f.exploits,
    timeline: timelineFor(f),
    batch: null,
    woke: null,
  };
}
