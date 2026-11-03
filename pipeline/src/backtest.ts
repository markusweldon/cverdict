/**
 * Receipts, part 2: the hindsight backtest. A reconstruction after the fact, never real time.
 *
 * For every CISA KEV addition of the last BACKTEST_DAYS days, each method is judged on the evidence
 * as it stood at the end of the day before the KEV dateAdded (the cutoff), wherever a source dates
 * its evidence:
 *
 *   time-matched  KEV prior (other listings before the cutoff), EPSS (the archived file of the day
 *                 before), Exploit-DB (date_added), PoC repos created and last pushed before the
 *                 cutoff (vetted by age at the cutoff), Metasploit modules whose earliest mod_time is before the cutoff, CISA
 *                 SSVC automatable and technical impact timestamped before the day before the
 *                 listing, and the CNA (or CISA-ADP) container when it has not changed since the
 *                 cutoff.
 *   hindsight     everything else that has no usable date: Nuclei templates, other Metasploit
 *                 modules, PoC repos pushed on the listing day or later, PoC star counts, SSVC stamped on the day before the listing or later,
 *                 the SSVC exploitation value in a changed container, CNA and CISA-ADP containers
 *                 changed since. The strict scores leave these out (as
 *                 unknown, never as absent); the `upper` variant ("with undated evidence") uses
 *                 today's values. Undated evidence is mostly exploits, so `upper` is usually higher,
 *                 but it is not a guaranteed bound (a low CVSS or a partial-impact SSVC costs points).
 *   excluded      the KEV listing itself, the CISA-ADP KEV block, today's EPSS score (it reacts to
 *                 the listing), and in `upper` an SSVC "exploitation: active" that cannot be
 *                 shown to predate the listing (lowered to poc or none, as in scripts/calibrate.ts).
 *
 *   today         vendor and product names, tags and descriptions: today's record in both
 *                 variants (the earlier text cannot be read). They name the product for the KEV
 *                 prior and mark noise; the page lists them as used as they are today.
 * The backtest only says whether each method would have flagged the CVE before the listing; it
 * does not estimate lead times (that needs the day each method first flagged it, which only the
 * forward log records).
 *
 * The hourly pipeline refreshes it when the carried-forward copy (previous receipts.json) is older
 * than BACKTEST_REFRESH_DAYS, so normal runs stay fast. scripts/backtest.ts runs it on demand.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  KNOB_DEFAULT,
  RECEIPT_METHODS,
  tierFor,
  type AlertVolume,
  type BacktestItem,
  type BacktestReceipts,
  type BacktestSet,
  type BacktestSignal,
  type MethodScore,
  type ReceiptMethod,
  type Row,
  type SourceId,
} from '../../shared/contract';
import { SCORE_MODEL } from '../../shared/model';
import { EPSS, type SanityLimits } from './config';
import { CVSS_LINE, EPSS_LINE } from './receipts';
import { firedChipIds } from './rows';
import { buildKevPrior, scoreCve } from './score';
import { parseEpssBodyOn } from './sources/epss';
import type { Enrichment, ExploitIndex, KevCatalog, KevPrior, KevRaw, Logger, NormalizedCve, PocRepo, ScoredCve } from './types';
import { addDays, DAY_MS, normalizeIso, normalizeYmd, ymd } from './util/dates';
import type { HttpClient } from './util/http';
import { asNumber, asObject } from './util/json';

export const BACKTEST_DAYS = 180;
export const BACKTEST_OLD_YEARS = 2;
export const BACKTEST_REFRESH_DAYS = 7;
export const BACKTEST_COMMAND = 'npm run backtest -- --help';
/** Parallel EPSS downloads during a refresh (each with its own cache slot of ~2 MB). */
export const EPSS_ASOF_SLOTS = 4;

/** Decided before ingest: what a refresh needs to download and keep. */
export interface BacktestPlan {
  /** Keep every record published from this instant on, for the alert volume over the period. */
  volumeFrom: Date;
  /** EPSS of the day before a listing, already known from the previous backtest: `${id}@${kev_added}`. */
  reuse: Map<string, { date: string; score: number | null }>;
  /** CVEs the previous backtest found published on or after their listing day: no EPSS needed. */
  skip: Set<string>;
}

/** Collected during ingest when the run refreshes the backtest. */
export interface BacktestInputs {
  /** EPSS score per listed CVE, by the day before its listing; null when that file could not be loaded. */
  epss: Map<string, Map<string, number> | null>;
  reuse: BacktestPlan['reuse'];
  /** Earliest Metasploit mod_time per CVE (ingested records only). */
  metasploitModified: Map<string, string>;
  /** Exploit-DB id → date_added. */
  exploitdbAdded: Map<string, string>;
  volumeFrom: string;
}

const reuseKey = (id: string, added: string) => `${id}@${added}`;
const cutoffOf = (dateAdded: string) => new Date(`${dateAdded}T00:00:00Z`);
const dayBefore = (dateAdded: string) => ymd(addDays(cutoffOf(dateAdded), -1));

/** KEV additions dated in the backtest range, newest first. */
export function backtestListings(kev: KevCatalog, now: Date): KevRaw[] {
  const from = ymd(addDays(now, -BACKTEST_DAYS));
  const to = ymd(now);
  return [...kev.entries.values()]
    .filter((k) => normalizeYmd(k.dateAdded) === k.dateAdded && k.dateAdded >= from && k.dateAdded <= to)
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || a.cveID.localeCompare(b.cveID));
}

// ── Carry-forward ──────────────────────────────────────────────────────────────────────────

/** The backtest in the previous receipts.json, if it looks like one of ours. Never throws. */
export function readPreviousBacktest(previousRoot: string | null): BacktestReceipts | null {
  if (!previousRoot) return null;
  try {
    const doc = asObject(JSON.parse(readFileSync(join(previousRoot, 'v1', 'receipts.json'), 'utf8')));
    const b = asObject(doc?.backtest);
    if (!b || b.hindsight !== true || !normalizeIso(b.computed_at) || !Array.isArray(b.items) || !Array.isArray(b.sets) || !Array.isArray(b.signals)) return null;
    return b as unknown as BacktestReceipts;
  } catch {
    return null;
  }
}

export interface BacktestDecision {
  /** Reuse this copy as is (null: refresh this run). */
  carried: BacktestReceipts | null;
  /** Set when the backtest is refreshed this run. */
  plan: BacktestPlan | null;
  note: string;
}

/**
 * What is wrong with a backtest object, if anything: its figures must match its items, and every
 * listing must be in a set or an exclusion. validate.ts runs it on every output; a carried copy that
 * fails it is recomputed instead (so a stricter build never gets stuck on an older copy).
 */
export function backtestProblems(b: BacktestReceipts): string[] {
  const out: string[] = [];
  if (!b || b.hindsight !== true || !Array.isArray(b.items) || !Array.isArray(b.sets)) return ['backtest is not marked as hindsight or is incomplete'];
  // Total over any JSON: a carried copy with a null set or item must be recomputed, never throw.
  const isObj = (v: unknown) => asObject(v) !== null;
  if (
    !b.sets.every((s) => isObj(s) && Array.isArray(s.strict) && Array.isArray(s.upper) && [...s.strict, ...s.upper].every(isObj)) ||
    !b.items.every((i) => isObj(i) && isObj(i.strict) && isObj(i.upper))
  ) {
    return ['backtest is incomplete'];
  }
  const total = b.sets.reduce((a, s) => a + s.n, 0);
  const excluded = (Array.isArray(b.excluded) ? b.excluded : []).reduce((a, e) => a + (Array.isArray(e?.ids) ? e.ids.length : 0), 0);
  if (total !== b.items.length || total + excluded !== b.listed) out.push(`backtest sets (${total}) and exclusions (${excluded}) do not add up to ${b.listed} listings`);
  for (const s of b.sets) {
    const items = b.items.filter((i) => i.old === (s.key === 'old'));
    for (const m of RECEIPT_METHODS) {
      for (const variant of ['strict', 'upper'] as const) {
        const score = s[variant].find((x) => x.method === m);
        const hits = items.filter((i) => i[variant][m]).length;
        if (!score || score.n !== s.n || score.before !== hits || score.lead !== null) out.push(`backtest ${s.key}.${variant}.${m} does not match its items`);
      }
    }
  }
  return out;
}

/**
 * Carry the previous backtest while it is younger than BACKTEST_REFRESH_DAYS. Refresh when there is
 * none, when it is from the future, from another score model or inconsistent, and a day after a
 * refresh that could not load some EPSS files or had a source down (those CVEs would otherwise
 * count as misses for a week).
 */
export function decideBacktest(previous: BacktestReceipts | null, now: Date, force = false): BacktestDecision {
  const age = previous ? now.getTime() - Date.parse(previous.computed_at) : NaN;
  const why = !previous
    ? null
    : force
      ? 'forced'
      : !(age >= 0 && age < BACKTEST_REFRESH_DAYS * DAY_MS)
        ? `computed ${previous.computed_at}`
        : previous.score_model !== SCORE_MODEL
          ? `score model ${previous.score_model ?? 'unknown'}, now ${SCORE_MODEL}`
          : Array.isArray(previous.epss_missing) && previous.epss_missing.length > 0 && age >= DAY_MS
            ? `${previous.epss_missing.length} EPSS days missing`
            : Array.isArray(previous.sources_down) && previous.sources_down.length > 0 && age >= DAY_MS
              ? `computed while ${previous.sources_down.join(', ')} had no data`
              : backtestProblems(previous)[0] ?? null;
  if (previous && why === null) {
    return { carried: previous, plan: null, note: `backtest carried forward (computed ${previous.computed_at})` };
  }
  const reuse: BacktestPlan['reuse'] = new Map();
  // Publication dates do not move, so a listing that came before its CVE was public stays excluded.
  const skip = new Set<string>();
  for (const e of Array.isArray(previous?.excluded) ? previous.excluded : []) if (e?.code === 'not_public' && Array.isArray(e.ids)) for (const id of e.ids) if (typeof id === 'string') skip.add(id);
  for (const it of Array.isArray(previous?.items) ? previous.items : []) {
    const date = normalizeYmd(it?.epss_date);
    const score = it?.epss === null ? null : asNumber(it?.epss);
    if (typeof it?.id === 'string' && typeof it.kev_added === 'string' && date && date === dayBefore(it.kev_added) && (it.epss === null || score !== null)) {
      reuse.set(reuseKey(it.id, it.kev_added), { date, score });
    }
  }
  return {
    carried: null,
    plan: { volumeFrom: addDays(now, -BACKTEST_DAYS), reuse, skip },
    note: previous ? `backtest refresh (previous: ${why}; ${reuse.size} EPSS values reused)` : 'backtest refresh (no previous backtest)',
  };
}

// ── EPSS of past days ──────────────────────────────────────────────────────────────────────

/**
 * For each day before a listing in the range, the EPSS scores of the CVEs listed the next day,
 * from the dated EPSS archive (then the EPSS host) through the cached source machinery.
 * EPSS_ASOF_SLOTS downloads run at once, each reusing its own cache slot for every day it fetches:
 * a past day never changes, and the results travel in receipts.json, so only the slots are cached.
 * Days whose every CVE is in `reuse` are not downloaded. Never throws.
 */
export async function loadEpssAsOf(
  http: HttpClient,
  kev: KevCatalog | null,
  now: Date,
  plan: Pick<BacktestPlan, 'reuse' | 'skip'>,
  limits: SanityLimits,
  log: Logger,
  signal?: AbortSignal,
): Promise<Map<string, Map<string, number> | null>> {
  const { reuse, skip } = plan;
  const out = new Map<string, Map<string, number> | null>();
  if (!kev) return out;
  const wanted = new Map<string, Set<string>>();
  for (const k of backtestListings(kev, now)) {
    if (reuse.has(reuseKey(k.cveID, k.dateAdded)) || skip.has(k.cveID)) continue;
    const day = dayBefore(k.dateAdded);
    let ids = wanted.get(day);
    if (!ids) wanted.set(day, (ids = new Set()));
    ids.add(k.cveID);
  }
  const started = performance.now();
  let failed = 0;
  const queue = [...wanted].sort((a, b) => a[0].localeCompare(b[0]));
  const worker = async (slot: number) => {
    for (let next = queue.shift(); next && !signal?.aborted; next = queue.shift()) await fetchDay(slot, ...next);
  };
  const fetchDay = async (slot: number, day: string, ids: Set<string>) => {
    const fetched = await http.getSource({
      key: `epss-asof-${slot}`,
      ext: 'csv.gz',
      urls: [EPSS.daily(day), EPSS.dated(day)],
      parse: (body) => {
        const parsed = parseEpssBodyOn(body, [day], limits);
        const picked = new Map<string, number>();
        for (const id of ids) {
          const s = parsed.value.scores.get(id);
          if (s) picked.set(id, s.epss);
        }
        return { ...parsed, value: picked };
      },
      signal,
    });
    if (!fetched.value) failed++;
    out.set(day, fetched.value);
  };
  await Promise.all(Array.from({ length: EPSS_ASOF_SLOTS }, (_, i) => worker(i)));
  log.info(`backtest: EPSS for ${wanted.size} past days (${failed} not loadable, ${reuse.size} values reused, ${skip.size} not needed) in ${((performance.now() - started) / 1000).toFixed(1)} s`);
  return out;
}

// ── Reconstruction ─────────────────────────────────────────────────────────────────────────

export const SIGNALS: readonly Omit<BacktestSignal, 'affected'>[] = [
  { key: 'kev', label: 'The KEV listing and the CISA-ADP KEV block', treatment: 'excluded', note: 'This is the answer, so it is never evidence.' },
  { key: 'epss_today', label: "Today's EPSS score", treatment: 'excluded', note: 'EPSS reacts to the listing. Only the file from the day before is used.' },
  {
    key: 'ssvc_active',
    label: 'A CISA SSVC "active" that may date from the listing',
    treatment: 'excluded',
    note: 'When CISA changed its part of the record after the listing day, the figures with undated evidence lower "active" to "poc" if a public exploit exists, else to "none".',
  },
  { key: 'kev_prior', label: 'Other KEV listings for the vendor or product', treatment: 'time_matched', note: 'Only listings dated before the listing day.' },
  { key: 'epss', label: 'EPSS', treatment: 'time_matched', note: 'The archived EPSS file from the day before. Left out when that file could not be loaded.' },
  { key: 'exploitdb', label: 'Exploit-DB', treatment: 'time_matched', note: 'Entries added before the listing day.' },
  {
    key: 'poc',
    label: 'PoC repos on GitHub',
    treatment: 'time_matched',
    note: 'Repos created and last changed before the listing day, so all their code is older than the listing. Repos deleted since cannot be seen.',
  },
  {
    key: 'poc_content',
    label: 'PoC repos changed on or after the listing day',
    treatment: 'hindsight',
    note: 'GitHub only gives the time of the last change, so the code may have come after the listing. These repos count only with undated evidence.',
  },
  {
    key: 'poc_stars',
    label: 'PoC star counts',
    treatment: 'hindsight',
    note: "Stars are only known for today, so a repo counts once it was 3 days old by the listing day. The figures with undated evidence also count today's stars.",
  },
  {
    key: 'metasploit',
    label: 'Metasploit modules',
    treatment: 'hindsight',
    note: 'Counted when a module was changed before the listing day, which proves it existed. Other modules count only with undated evidence.',
  },
  { key: 'nuclei', label: 'Nuclei templates', treatment: 'hindsight', note: 'The template list has no dates, so templates count only with undated evidence.' },
  {
    key: 'ssvc',
    label: 'CISA SSVC automatable and technical impact',
    treatment: 'hindsight',
    note: 'Counted when CISA dated the assessment at least two days before the listing, or has not changed its part of the record since. CISA often dates the update it makes for a listing with the day before, so a later date counts only with undated evidence.',
  },
  {
    key: 'ssvc_exploitation',
    label: 'CISA SSVC exploitation ("poc" or "active")',
    treatment: 'hindsight',
    note: 'Counted only when CISA has not changed its part of the record since the listing day. CISA updates this value when it lists a CVE, and often dates it the day before, so its date cannot be trusted.',
  },
  {
    key: 'cna_record',
    label: 'CNA CVSS, CVSS exploit maturity and "exploited in the wild" text',
    treatment: 'hindsight',
    note: 'Counted when the CNA has not changed its part of the record since the listing day. Otherwise only with undated evidence.',
  },
  {
    key: 'adp_cvss',
    label: 'CISA-ADP CVSS (when the CNA gave none)',
    treatment: 'hindsight',
    note: 'Counted when CISA has not changed its part of the record since the listing day. Otherwise only with undated evidence.',
  },
  {
    key: 'record_text',
    label: 'Vendor and product names, tags and description',
    treatment: 'today',
    note: 'Used as they read today in every figure, because the earlier text cannot be read. They name the product for the KEV history check and mark likely noise, such as WordPress plugins and disputed CVEs.',
  },
];

export interface AsOfEvidence {
  cve: NormalizedCve;
  enr: Enrichment;
  /** Signal keys left out (strict) or changed from today's value (upper: `ssvc_active`). */
  leftOut: string[];
}

export interface AsOfInput {
  cve: NormalizedCve;
  kev: KevRaw;
  /** Today's enrichment of the run (exploits, unavailable sources). */
  enr: Enrichment;
  /** KEV catalog and prior as of the cutoff (without this CVE). */
  kevAsOf: { catalog: KevCatalog; prior: KevPrior };
  /** EPSS of the day before (null: no file); `scores` holds the CVE when EPSS scored it that day. */
  epss: { date: string; score: number | null } | null;
  metasploitModified: ReadonlyMap<string, string>;
  exploitdbAdded: ReadonlyMap<string, string>;
}

const before = (iso: string | null | undefined, cutoffMs: number) => !!iso && Date.parse(iso) < cutoffMs;

/** The CVE and its enrichment as of the cutoff, in one variant. Pure. */
export function evidenceAsOf(input: AsOfInput, variant: 'strict' | 'upper'): AsOfEvidence {
  const { cve, kev, enr } = input;
  const strict = variant === 'strict';
  const cutoff = cutoffOf(kev.dateAdded);
  const cutoffMs = cutoff.getTime();
  const lastDay = dayBefore(kev.dateAdded);
  const leftOut: string[] = [];
  const unavailable = new Map<SourceId, string>(enr.unavailable);

  // Exploit artifacts.
  const msf = enr.exploits.metasploit.get(cve.id) ?? [];
  const msfDated = msf.length > 0 && before(input.metasploitModified.get(cve.id), cutoffMs);
  let metasploit = msf;
  if (msf.length > 0 && !msfDated && strict) {
    metasploit = [];
    leftOut.push('metasploit');
    unavailable.set('metasploit', 'Metasploit (no usable date)');
  }
  let nuclei = enr.exploits.nuclei.get(cve.id) ?? [];
  if (nuclei.length > 0 && strict) {
    nuclei = [];
    leftOut.push('nuclei');
    unavailable.set('nuclei', 'Nuclei templates (no dates)');
  }
  const exploitdb = (enr.exploits.exploitdb.get(cve.id) ?? []).filter((e) => {
    const date = input.exploitdbAdded.get(e.id) ?? e.date;
    return date !== null && date <= lastDay;
  });
  // A repo created before the cutoff may only have gained its code later: strictly, it counts only
  // when its last push is before the cutoff too (all its content is then older than the listing).
  const allRepos = (enr.exploits.poc.get(cve.id) ?? []).filter((r) => before(r.created, cutoffMs));
  const pushedBefore = allRepos.filter((r) => before(r.pushed, cutoffMs));
  const repos: PocRepo[] = strict ? pushedBefore.map((r) => ({ ...r, stars: 0 })) : allRepos;
  if (strict && pushedBefore.length < allRepos.length) leftOut.push('poc_content');
  if (strict && pushedBefore.some((r) => r.stars > 0)) leftOut.push('poc_stars');

  // SSVC. The timestamp dates the assessment, but CISA changes the exploitation value when it lists
  // a CVE, and only today's container can be read. So the exploitation value is time-matched only
  // when CISA's container is unchanged since the cutoff. Automatable and technical impact are
  // time-matched by the timestamp, which must be before the day before the listing: CISA often
  // stamps the assessment it rewrites at the listing with the day before (a clear spike in the
  // data), so a stamp on that day cannot be told apart from the listing.
  let ssvc = cve.ssvc;
  const adpDated = before(cve.adpUpdated, cutoffMs);
  if (ssvc && !adpDated) {
    const lowered = () => {
      const artifact = metasploit.length + nuclei.length + exploitdb.length + repos.filter((r) => !r.fork).length > 0;
      return artifact ? 'poc' : 'none';
    };
    if (strict && !before(ssvc.timestamp, cutoffMs - DAY_MS)) {
      ssvc = null;
      leftOut.push('ssvc');
    } else if (strict && (ssvc.exploitation === 'active' || ssvc.exploitation === 'poc')) {
      ssvc = { ...ssvc, exploitation: '' };
      leftOut.push('ssvc_exploitation');
    } else if (!strict && ssvc.exploitation === 'active') {
      ssvc = { ...ssvc, exploitation: lowered() };
      leftOut.push('ssvc_active');
    }
  }

  // CNA and CISA-ADP containers. Only the chosen CVSS is known (CNA first), so when a changed CNA
  // container is left out, an older CISA-ADP score is not recovered: the strict CVSS is then unknown.
  let { cvss, cvssMetrics, cnaCvssMissing, cnaExploitMaturity, vendorInTheWild } = cve;
  const cnaDated = before(cve.cnaUpdated, cutoffMs);
  if (strict && !cnaDated) {
    if (cvss?.source === 'cna' || cnaExploitMaturity.length > 0 || vendorInTheWild) leftOut.push('cna_record');
    cnaExploitMaturity = [];
    vendorInTheWild = false;
    if (cvss?.source === 'cna') cvss = null;
  }
  if (strict && cvss?.source === 'cisa-adp' && !before(cve.adpUpdated, cutoffMs)) {
    cvss = null;
    leftOut.push('adp_cvss');
  }
  if (!cvss) {
    cvssMetrics = {};
    cnaCvssMissing = true;
  }

  // EPSS of the day before.
  const scores = new Map<string, { epss: number; percentile: number }>();
  if (input.epss?.score != null) scores.set(cve.id, { epss: input.epss.score, percentile: 0 });
  if (!input.epss) unavailable.set('epss', 'EPSS (no file for the day before)');

  return {
    cve: { ...cve, adpKev: null, ssvc, cvss, cvssMetrics, cnaCvssMissing, cnaExploitMaturity, vendorInTheWild },
    enr: {
      kev: input.kevAsOf.catalog,
      prior: input.kevAsOf.prior,
      epss: { model: null, scoreDate: input.epss?.date ?? null, scores },
      exploits: {
        metasploit: new Map(metasploit.length ? [[cve.id, metasploit]] : []),
        nuclei: new Map(nuclei.length ? [[cve.id, nuclei]] : []),
        exploitdb: new Map(exploitdb.length ? [[cve.id, exploitdb]] : []),
        poc: new Map(repos.length ? [[cve.id, repos]] : []),
      } satisfies ExploitIndex,
      unavailable,
    },
    leftOut,
  };
}

/** The KEV catalog as of the start of `dateAdded`: entries listed on earlier days only. */
export function kevAsOf(kev: KevCatalog, dateAdded: string): KevCatalog {
  return { version: null, dateReleased: null, entries: new Map([...kev.entries].filter(([, k]) => k.dateAdded < dateAdded)) };
}

const passed = (s: ScoredCve) => {
  const t = tierFor(s.score, s.exploited, s.weaponized, KNOB_DEFAULT);
  return t === 'exploited' || t === 'likely';
};

function setScores(items: readonly BacktestItem[], pick: (i: BacktestItem) => Record<ReceiptMethod, boolean>): MethodScore[] {
  return RECEIPT_METHODS.map((method) => {
    const hits = items.filter((i) => pick(i)[method]).length;
    // Judged as of the end of the day before: every hit is at least a day earlier.
    return { method, n: items.length, before: hits, earlier: hits, same_day: 0, lead: null };
  });
}

export interface BacktestInput {
  now: Date;
  kev: KevCatalog;
  /** Ingested records by id (KEV records are always ingested). */
  cves: ReadonlyMap<string, NormalizedCve>;
  /** Today's enrichment of the run. */
  enr: Enrichment;
  inputs: BacktestInputs;
  /** Every record scored this run, for the alert volume (needs the period's records). */
  scored: readonly ScoredCve[];
  rows: ReadonlyMap<string, Row>;
}

export function runBacktest({ now, kev, cves, enr, inputs, scored, rows }: BacktestInput): BacktestReceipts {
  const listings = backtestListings(kev, now);
  const priors = new Map<string, { catalog: KevCatalog; prior: KevPrior }>();
  const asOfKev = (date: string) => {
    let p = priors.get(date);
    if (!p) {
      const catalog = kevAsOf(kev, date);
      priors.set(date, (p = { catalog, prior: buildKevPrior(catalog) }));
    }
    return p;
  };
  const noRecord: string[] = [];
  const notYet: string[] = [];
  const items: BacktestItem[] = [];
  const affected = new Map<string, number>();
  const epssMissing = new Set<string>();
  for (const k of listings) {
    const cve = cves.get(k.cveID);
    if (!cve) {
      noRecord.push(k.cveID);
      continue;
    }
    const cutoff = cutoffOf(k.dateAdded);
    if (Date.parse(cve.published) >= cutoff.getTime()) {
      notYet.push(k.cveID);
      continue;
    }
    const day = dayBefore(k.dateAdded);
    const reused = inputs.reuse.get(reuseKey(k.cveID, k.dateAdded));
    const file = inputs.epss.get(day);
    const epss = reused ?? (file ? { date: day, score: file.get(k.cveID) ?? null } : null);
    if (!epss) {
      epssMissing.add(day);
      affected.set('epss', (affected.get('epss') ?? 0) + 1);
    }
    const input: AsOfInput = { cve, kev: k, enr, kevAsOf: asOfKev(k.dateAdded), epss, metasploitModified: inputs.metasploitModified, exploitdbAdded: inputs.exploitdbAdded };
    const strict = evidenceAsOf(input, 'strict');
    const upper = evidenceAsOf(input, 'upper');
    const s = scoreCve(strict.cve, strict.enr, { now: cutoff, knob: KNOB_DEFAULT });
    const u = scoreCve(upper.cve, upper.enr, { now: cutoff, knob: KNOB_DEFAULT });
    for (const key of [...strict.leftOut, ...upper.leftOut]) affected.set(key, (affected.get(key) ?? 0) + 1);
    const epssHit = (epss?.score ?? -1) >= EPSS_LINE;
    const old = Date.parse(cve.published) < Date.UTC(cutoff.getUTCFullYear() - BACKTEST_OLD_YEARS, cutoff.getUTCMonth(), cutoff.getUTCDate());
    items.push({
      id: k.cveID,
      kev_added: k.dateAdded,
      published: cve.published,
      old,
      strict: { cverdict: passed(s), cvss7: (strict.cve.cvss?.score ?? -1) >= CVSS_LINE, epss10: epssHit },
      upper: { cverdict: passed(u), cvss7: (upper.cve.cvss?.score ?? -1) >= CVSS_LINE, epss10: epssHit },
      score: s.score,
      chips: firedChipIds(s.reasons),
      cvss: strict.cve.cvss?.score ?? null,
      epss: epss?.score ?? null,
      epss_date: epss?.date ?? null,
      left_out: strict.leftOut,
      row: rows.get(k.cveID) ?? null,
    });
  }

  const sets: BacktestSet[] = (['recent', 'old'] as const).map((key) => {
    const set = items.filter((i) => i.old === (key === 'old'));
    return { key, n: set.length, strict: setScores(set, (i) => i.strict), upper: setScores(set, (i) => i.upper) };
  });

  const from = ymd(addDays(now, -BACKTEST_DAYS));
  const volumeFrom = Date.parse(inputs.volumeFrom);
  const period = scored.filter((s) => {
    const t = Date.parse(s.cve.published);
    return t >= volumeFrom && t <= now.getTime();
  });
  const volume: AlertVolume[] = [
    { method: 'cverdict', n: period.length, flagged: period.filter(passed).length },
    { method: 'cvss7', n: period.length, flagged: period.filter((s) => (s.cve.cvss?.score ?? -1) >= CVSS_LINE).length },
    { method: 'epss10', n: period.length, flagged: period.filter((s) => (s.epss?.score ?? -1) >= EPSS_LINE).length },
  ];

  return {
    hindsight: true,
    computed_at: now.toISOString(),
    score_model: SCORE_MODEL,
    from,
    to: ymd(now),
    days: BACKTEST_DAYS,
    old_years: BACKTEST_OLD_YEARS,
    listed: listings.length,
    excluded: (
      [
        { code: 'no_record', reason: 'No published CVE record', ids: noRecord },
        { code: 'not_public', reason: 'Published on or after the listing day, so no method could flag it before', ids: notYet },
      ] as const
    )
      .filter((e) => e.ids.length > 0)
      .map((e) => ({ ...e, ids: [...e.ids] })),
    sets,
    volume: period.length > 0 ? { from: new Date(volumeFrom).toISOString(), n: period.length, methods: volume } : null,
    // The listing and today's EPSS are set aside for every CVE in the backtest.
    signals: SIGNALS.map((s) => ({ ...s, affected: s.key === 'kev' || s.key === 'epss_today' || s.treatment === 'today' ? items.length : (affected.get(s.key) ?? 0) })),
    epss_missing: [...epssMissing].sort(),
    sources_down: [...enr.unavailable.values()].sort(),
    items,
    command: BACKTEST_COMMAND,
  };
}
