/**
 * Aggregates for the surge page and the signal waterfall (StatsFile).
 */
import { NEW_EXPLOITED_HOURS, SCHEMA_VERSION, TIERS, type StatsFile, type Tier } from '../../shared/contract';
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

/**
 * True when an Exploited CVE got its first exploited signal within NEW_EXPLOITED_HOURS of `now`.
 * The signals are the ones that set the tier: a CISA KEV, ENISA EU KEV or CIRCL listing, CISA SSVC
 * "exploitation active", and the CNA's own exploited flag. The first one decides, so a CVE already
 * Exploited through SSVC does not turn new when KEV lists it later.
 * - Listings carry a day only, so a day counts from its start (00:00 UTC). That never calls a
 *   listing new when it may be older than 72 hours.
 * - SSVC counts from its timestamp; the CNA flag from the CVE's publication, the earliest it can be.
 * - A signal with no date could be older, so it rules the CVE out (an EU KEV row known not to
 *   predate the CISA day is bounded by that day instead).
 * - Signals dated after `now` do not exist yet. The boundary (now - 72h) is inclusive.
 */
export function isNewlyExploited(s: ScoredCve, listings: readonly CatalogListing[] | undefined, now: Date): boolean {
  if (s.tier !== 'exploited') return false;
  const today = ymd(now);
  const times: number[] = [];
  const day = (d: string) => Date.parse(`${d}T00:00:00Z`);
  if (s.kev || s.cve.adpKev) {
    const kevDay = normalizeYmd(s.kev?.date_added ?? s.cve.adpKev?.dateAdded);
    if (!kevDay) return false;
    times.push(day(kevDay));
  }
  for (const l of listings ?? []) {
    if (!isExploitedListing(l, today)) continue;
    if (l.added) times.push(day(l.added));
    // Undated but known not to predate another listing (EU KEV after the CISA day): that listing decides.
    else if (!l.notBefore) return false;
  }
  if (s.cve.ssvc?.exploitation === 'active') {
    const at = s.cve.ssvc.timestamp ? Date.parse(s.cve.ssvc.timestamp) : NaN;
    if (Number.isNaN(at)) return false;
    times.push(at);
  }
  if (vendorSaysExploited(s.cve)) times.push(Date.parse(s.cve.published));
  const past = times.filter((t) => !Number.isNaN(t) && t <= now.getTime());
  if (past.length === 0) return false;
  return Math.min(...past) >= now.getTime() - NEW_EXPLOITED_HOURS * HOUR_MS;
}

function hourly(window: ScoredCve[], windowStart: Date, now: Date, catalogs?: StatsInput['catalogs']): StatsFile['hourly'] {
  const start = Math.floor(windowStart.getTime() / HOUR_MS) * HOUR_MS;
  const hours = Math.max(1, Math.ceil((now.getTime() - start) / HOUR_MS));
  const counts = Array.from({ length: hours }, () => [0, 0, 0, 0] as [number, number, number, number]);
  const fresh = new Map<number, number>();
  for (const s of window) {
    const h = Math.floor((Date.parse(s.cve.published) - start) / HOUR_MS);
    if (h < 0 || h >= hours) continue;
    counts[h][TIERS.indexOf(s.tier)]++;
    if (isNewlyExploited(s, catalogs?.get(s.cve.id), now)) fresh.set(h, (fresh.get(h) ?? 0) + 1);
  }
  const newExploited = [...fresh.entries()].sort((a, b) => a[0] - b[0]);
  return { start: new Date(start).toISOString(), hours, counts, new_exploited: newExploited };
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

export function buildStats({ history, kev, window, windowStart, now, catalogs }: StatsInput): StatsFile {
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: now.toISOString(),
    monthly: monthly(history, kev, now),
    daily: daily(window, windowStart, now),
    hourly: hourly(window, windowStart, now, catalogs),
    cnas: cnas(window),
    ai_credits: aiCredits(window),
  };
}
