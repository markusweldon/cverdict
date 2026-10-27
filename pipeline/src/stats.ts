/**
 * Aggregates for the surge page and the signal waterfall (StatsFile).
 */
import { SCHEMA_VERSION, TIERS, type StatsFile, type Tier } from '../../shared/contract';
import { utcDay } from './score';
import type { History, KevCatalog, ScoredCve } from './types';
import { DAY_MS, monthKey, ymd } from './util/dates';

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

function daily(window: ScoredCve[], windowStart: Date, now: Date): StatsFile['daily'] {
  const days = new Map(dayRange(windowStart, now).map((date) => [date, { date, published: 0, passed: 0, exploited: 0 }]));
  for (const s of window) {
    const d = days.get(utcDay(s.cve.published));
    if (!d) continue;
    d.published++;
    if (isPassed(s.tier)) d.passed++;
    if (s.tier === 'exploited') d.exploited++;
  }
  return [...days.values()];
}

function hourly(window: ScoredCve[], windowStart: Date, now: Date): StatsFile['hourly'] {
  const start = Math.floor(windowStart.getTime() / HOUR_MS) * HOUR_MS;
  const hours = Math.max(1, Math.ceil((now.getTime() - start) / HOUR_MS));
  const counts = Array.from({ length: hours }, () => [0, 0, 0, 0] as [number, number, number, number]);
  for (const s of window) {
    const h = Math.floor((Date.parse(s.cve.published) - start) / HOUR_MS);
    if (h >= 0 && h < hours) counts[h][TIERS.indexOf(s.tier)]++;
  }
  return { start: new Date(start).toISOString(), hours, counts };
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

export function buildStats({ history, kev, window, windowStart, now }: StatsInput): StatsFile {
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: now.toISOString(),
    monthly: monthly(history, kev, now),
    daily: daily(window, windowStart, now),
    hourly: hourly(window, windowStart, now),
    cnas: cnas(window),
    ai_credits: aiCredits(window),
  };
}
