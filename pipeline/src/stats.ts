/**
 * Aggregates for the surge page and the signal waterfall (StatsFile).
 */
import { cnaName, vendorProduct } from '../../shared/cna';
import { NEW_EXPLOITED_HOURS, NEW_EXPLOITED_LIST_MAX, NEW_EXPLOITED_VIA, SCHEMA_VERSION, TIERS, type NewExploitedCve, type NewExploitedVia, type StatsFile, type Tier } from '../../shared/contract';
import { utcDay, vendorSaysExploited } from './score';
import { isExploitedListing } from './sources/catalogs';
import type { CatalogListing, History, KevCatalog, ScoredCve } from './types';
import { DAY_MS, monthKey, normalizeYmd, ymd } from './util/dates';

/** The first CVE identifiers were published in 1999. */
const FIRST_MONTH = '1999-01';
const HOUR_MS = 3_600_000;
const TOP_CNAS = 25;
const TOP_AI_CREDITS = 20;

export interface StatsInput {
  history: History;
  kev: KevCatalog;
  /** Scored records published inside the window (tiers at the default knob). */
  window: ScoredCve[];
  windowStart: Date;
  now: Date;
  /** Listings in the other known-exploited catalogs per CVE (EU KEV, CIRCL, SiberKapan), if loaded. */
  catalogs?: ReadonlyMap<string, readonly CatalogListing[]>;
  /** Scored records published before the window (KEV, catalog and woke CVEs): newly listed ones join hourly.new_exploited_cves. */
  outside?: readonly ScoredCve[];
}

const isPassed = (t: Tier) => t === 'exploited' || t === 'likely';

/** "YYYY-MM" for every month from `from` to `to` inclusive. */
export function monthRange(from: string, to: string): string[] {
  const out: string[] = [];
  let [y, m] = from.split('-').map(Number);
  const [ty, tm] = to.split('-').map(Number);
  while (y < ty || (y === ty && m <= tm)) {
    out.push(`${y}-${String(m).padStart(2, '0')}`);
    if (++m > 12) {
      m = 1;
      y++;
    }
  }
  return out;
}

/** "YYYY-MM-DD" for every UTC day from `from` to `to` inclusive. */
export function dayRange(from: Date, to: Date): string[] {
  const out: string[] = [];
  for (let t = Date.parse(ymd(from)); t <= to.getTime(); t += DAY_MS) out.push(ymd(new Date(t)));
  return out;
}

function monthly(history: History, kev: KevCatalog, now: Date): StatsFile['monthly'] {
  const kevAdded = new Map<string, number>();
  for (const e of kev.entries.values()) {
    const m = e.dateAdded.slice(0, 7);
    kevAdded.set(m, (kevAdded.get(m) ?? 0) + 1);
  }
  return monthRange(FIRST_MONTH, monthKey(now)).map((month) => ({
    month,
    published: history.published.get(month) ?? 0,
    reserved: history.reserved.get(month) ?? 0,
    rejected: history.rejected.get(month) ?? 0,
    ai: history.ai.get(month) ?? 0,
    kev_added: kevAdded.get(month) ?? 0,
  }));
}

/**
 * Full UTC days from the first midnight at or after windowStart, then today so far. The day the
 * window starts in is left out: only its last hours are in the window, so it would read as a dip.
 */
function daily(window: ScoredCve[], windowStart: Date, now: Date): StatsFile['daily'] {
  const firstDay = new Date(Math.ceil(windowStart.getTime() / DAY_MS) * DAY_MS);
  const days = new Map(dayRange(firstDay, now).map((date) => [date, { date, published: 0, passed: 0, exploited: 0 }]));
  for (const s of window) {
    const d = days.get(utcDay(s.cve.published));
    if (!d) continue;
    d.published++;
    if (isPassed(s.tier)) d.passed++;
    if (s.tier === 'exploited') d.exploited++;
  }
  return [...days.values()];
}

/** The first exploited signal of a newly exploited CVE: when (as written in stats.json, and in ms) and which one. */
export interface FirstSignal {
  at: string;
  ms: number;
  via: NewExploitedVia;
}

const LISTING_VIA: Partial<Record<CatalogListing['catalog'], NewExploitedVia>> = { 'eu-kev': 'EU KEV', 'circl-kev': 'CIRCL' };

/**
 * The first exploited signal of an Exploited CVE, when that signal is within NEW_EXPLOITED_HOURS of
 * `now`; null otherwise. The signals are the ones that set the tier: a CISA KEV, ENISA EU KEV or
 * CIRCL listing, CISA SSVC "exploitation active", and the CNA's own exploited flag. The first one
 * decides, so a CVE already Exploited through SSVC does not turn new when KEV lists it later.
 * - Listings carry a day only, so a day counts from its start (00:00 UTC). That never calls a
 *   listing new when it may be older than 72 hours.
 * - SSVC counts from its timestamp; the CNA flag from the CVE's publication, the earliest it can be.
 * - A signal with no date could be older, so it rules the CVE out (an EU KEV row known not to
 *   predate the CISA day is bounded by that day instead).
 * - Signals dated after `now` do not exist yet. The boundary (now - 72h) is inclusive.
 * - Two signals at the same time: the one listed first above is named.
 */
export function firstExploitedSignal(s: ScoredCve, listings: readonly CatalogListing[] | undefined, now: Date): FirstSignal | null {
  if (s.tier !== 'exploited') return null;
  const today = ymd(now);
  const signals: FirstSignal[] = [];
  const onDay = (d: string, via: NewExploitedVia) => signals.push({ at: d, ms: Date.parse(`${d}T00:00:00Z`), via });
  if (s.kev || s.cve.adpKev) {
    const kevDay = normalizeYmd(s.kev?.date_added ?? s.cve.adpKev?.dateAdded);
    if (!kevDay) return null;
    onDay(kevDay, 'CISA KEV');
  }
  for (const l of listings ?? []) {
    const via = LISTING_VIA[l.catalog];
    if (!via || !isExploitedListing(l, today)) continue;
    if (l.added) onDay(l.added, via);
    // Undated but known not to predate another listing (EU KEV after the CISA day): that listing decides.
    else if (!l.notBefore) return null;
  }
  if (s.cve.ssvc?.exploitation === 'active') {
    const ms = s.cve.ssvc.timestamp ? Date.parse(s.cve.ssvc.timestamp) : NaN;
    if (Number.isNaN(ms)) return null;
    signals.push({ at: new Date(ms).toISOString(), ms, via: 'CISA SSVC' });
  }
  if (vendorSaysExploited(s.cve)) {
    const ms = Date.parse(s.cve.published);
    if (!Number.isNaN(ms)) signals.push({ at: new Date(ms).toISOString(), ms, via: 'Vendor' });
  }
  let first: FirstSignal | null = null;
  for (const sig of signals) if (!Number.isNaN(sig.ms) && sig.ms <= now.getTime() && (!first || sig.ms < first.ms)) first = sig;
  return first && first.ms >= now.getTime() - NEW_EXPLOITED_HOURS * HOUR_MS ? first : null;
}

/** The signals named first when two come at the same time (the order of NEW_EXPLOITED_VIA). */
const viaRank = (v: NewExploitedVia) => NEW_EXPLOITED_VIA.indexOf(v);

/**
 * The exploited catalog listings of a CVE dated within NEW_EXPLOITED_HOURS of `now`: a CISA KEV
 * dateAdded (or the CVE record's ADP copy of it), an ENISA EU KEV listing, a confirmed CIRCL
 * listing. Days count from 00:00 UTC, as in firstExploitedSignal. A new listing is news even when
 * the CVE was already Exploited through an earlier signal, and whatever the CVE's age.
 */
export function freshListings(s: ScoredCve, listings: readonly CatalogListing[] | undefined, now: Date): FirstSignal[] {
  const today = ymd(now);
  const from = now.getTime() - NEW_EXPLOITED_HOURS * HOUR_MS;
  const out: FirstSignal[] = [];
  const onDay = (d: string | null | undefined, via: NewExploitedVia) => {
    const ms = d ? Date.parse(`${d}T00:00:00Z`) : NaN;
    if (d && ms >= from && ms <= now.getTime()) out.push({ at: d, ms, via });
  };
  onDay(normalizeYmd(s.kev?.date_added ?? s.cve.adpKev?.dateAdded), 'CISA KEV');
  for (const l of listings ?? []) {
    const via = LISTING_VIA[l.catalog];
    if (via && isExploitedListing(l, today)) onDay(l.added, via);
  }
  return out;
}

/**
 * The signal that makes an Exploited CVE newly exploited, or null. Newly exploited means its first
 * exploited signal is within NEW_EXPLOITED_HOURS (firstExploitedSignal), or a catalog listing is
 * (freshListings). The newest of those is named, so a CVE Exploited through SSVC a month ago and
 * listed by CISA KEV yesterday reads "CISA KEV". With `inWindow` false (a CVE published before the
 * window, so not on the chart) only the listings count.
 */
export function newlyExploitedSignal(s: ScoredCve, listings: readonly CatalogListing[] | undefined, now: Date, inWindow = true): FirstSignal | null {
  if (s.tier !== 'exploited') return null;
  const first = inWindow ? firstExploitedSignal(s, listings, now) : null;
  let pick: FirstSignal | null = null;
  for (const sig of [...(first ? [first] : []), ...freshListings(s, listings, now)]) {
    if (!pick || sig.ms > pick.ms || (sig.ms === pick.ms && viaRank(sig.via) < viaRank(pick.via))) pick = sig;
  }
  return pick;
}

/** True when an Exploited CVE in the window is newly exploited (see newlyExploitedSignal). */
export const isNewlyExploited = (s: ScoredCve, listings: readonly CatalogListing[] | undefined, now: Date): boolean => newlyExploitedSignal(s, listings, now) !== null;

const TITLE_MAX = 80;

/** The short name the site shows for a CVE: "Vendor · Product", else the CNA's display name, else the CVE ID. */
export function shortTitle(s: ScoredCve): string {
  const first = s.cve.affected[0];
  const text = ((first ? vendorProduct(first.vendor, first.product) : '') || cnaName(s.cve.cna)).replace(/\s+/g, ' ').trim() || s.cve.id;
  return text.length > TITLE_MAX ? `${text.slice(0, TITLE_MAX - 1).trimEnd()}…` : text;
}

/**
 * The hour buckets, and the newly exploited CVEs: those in the window by their publication hour
 * (the ticks that pulse), then those published before it (`outside`, no hour, not on the chart).
 */
function hourly(window: ScoredCve[], windowStart: Date, now: Date, catalogs?: StatsInput['catalogs'], outside: readonly ScoredCve[] = []): StatsFile['hourly'] {
  const start = Math.floor(windowStart.getTime() / HOUR_MS) * HOUR_MS;
  const hours = Math.max(1, Math.ceil((now.getTime() - start) / HOUR_MS));
  const counts = Array.from({ length: hours }, () => [0, 0, 0, 0] as [number, number, number, number]);
  const fresh: (NewExploitedCve & { ms: number })[] = [];
  const seen = new Set<string>();
  for (const s of window) {
    const h = Math.floor((Date.parse(s.cve.published) - start) / HOUR_MS);
    if (h < 0 || h >= hours) continue;
    counts[h][TIERS.indexOf(s.tier)]++;
    seen.add(s.cve.id);
    const sig = newlyExploitedSignal(s, catalogs?.get(s.cve.id), now);
    if (sig) fresh.push({ id: s.cve.id, title: shortTitle(s), via: sig.via, at: sig.at, hour: h, ms: sig.ms });
  }
  for (const s of outside) {
    const pub = Date.parse(s.cve.published);
    if (seen.has(s.cve.id) || !(pub < start)) continue;
    seen.add(s.cve.id);
    const sig = newlyExploitedSignal(s, catalogs?.get(s.cve.id), now, false);
    if (sig) fresh.push({ id: s.cve.id, title: shortTitle(s), via: sig.via, at: sig.at, published: ymd(new Date(pub)), ms: sig.ms });
  }
  // One list for every field, so the count, the pulsing ticks and the names never disagree.
  fresh.sort((a, b) => b.ms - a.ms || a.id.localeCompare(b.id));
  const perHour = new Map<number, number>();
  for (const f of fresh) if (f.hour !== undefined) perHour.set(f.hour, (perHour.get(f.hour) ?? 0) + 1);
  const newExploited = [...perHour.entries()].sort((a, b) => a[0] - b[0]);
  const cves = fresh.slice(0, NEW_EXPLOITED_LIST_MAX).map(({ ms: _ms, ...c }) => c);
  return { start: new Date(start).toISOString(), hours, counts, new_exploited: newExploited, new_exploited_cves: cves, new_exploited_total: fresh.length };
}

function cnas(window: ScoredCve[]): StatsFile['cnas'] {
  const by = new Map<string, StatsFile['cnas'][number]>();
  for (const s of window) {
    const cna = s.cve.cna;
    const c = by.get(cna) ?? { cna, count: 0, passed: 0, no_cvss: 0, ssvc_missing: 0 };
    c.count++;
    if (isPassed(s.tier)) c.passed++;
    if (s.cve.cnaCvssMissing) c.no_cvss++;
    if (!s.cve.ssvc) c.ssvc_missing++;
    by.set(cna, c);
  }
  return [...by.values()].sort((a, b) => b.count - a.count || a.cna.localeCompare(b.cna)).slice(0, TOP_CNAS);
}

/** Credit strings grouped case-insensitively; the most frequent (then first-seen) spelling is shown. */
function aiCredits(window: ScoredCve[]): StatsFile['ai_credits'] {
  const groups = new Map<string, Map<string, number>>();
  for (const s of window) {
    const text = s.cve.aiCredit?.trim();
    if (!text) continue;
    const key = text.toLowerCase();
    const spellings = groups.get(key) ?? new Map<string, number>();
    spellings.set(text, (spellings.get(text) ?? 0) + 1);
    groups.set(key, spellings);
  }
  return [...groups.values()]
    .map((spellings) => {
      const [text] = [...spellings.entries()].sort((a, b) => b[1] - a[1])[0];
      return { text, count: [...spellings.values()].reduce((a, b) => a + b, 0) };
    })
    .sort((a, b) => b.count - a.count || a.text.localeCompare(b.text))
    .slice(0, TOP_AI_CREDITS);
}

export function buildStats({ history, kev, window, windowStart, now, catalogs, outside }: StatsInput): StatsFile {
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: now.toISOString(),
    monthly: monthly(history, kev, now),
    daily: daily(window, windowStart, now),
    hourly: hourly(window, windowStart, now, catalogs, outside),
    cnas: cnas(window),
    ai_credits: aiCredits(window),
  };
}
