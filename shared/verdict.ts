/**
 * The plain-language verdict of one CVE ("Patch now: exploited, KEV due Oct 29"), shared by the CVE
 * page, the ticket and the link-preview text (shared/share.ts).
 *
 * Pure and runtime-free: imports carry `.js` extensions because api/share.ts runs this as plain
 * Node ESM. Dates are UTC days; the reference year is passed in, so a preview built from a run in
 * December still reads "Dec 30" in January. No formatter here returns a placeholder for a missing
 * value: it returns null and the caller leaves that part out.
 */
import { KNOB_DEFAULT, WATCH_FLOOR, type CveDetail, type Reason, type Tier } from './contract.js';

/** Tier names as they read in sentences and previews. */
export const TIER_NAMES: Readonly<Record<Tier, string>> = { exploited: 'Exploited', likely: 'Likely next', watch: 'Watch', quiet: 'Quiet' };

/** The headline of each tier's verdict. */
export const VERDICT_HEADS: Readonly<Record<Tier, string>> = { exploited: 'Patch now', likely: 'Likely next', watch: 'Watch', quiet: 'Quiet' };

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})(?:$|T\d{2}:\d{2})/;

/** Year, month (0-11) and day of a YYYY-MM-DD date or an ISO date-time (its UTC day), or null. */
function utcDay(value: unknown): { y: number; m: number; d: number } | null {
  if (typeof value !== 'string' || value.length > 40) return null;
  const match = DAY_RE.exec(value);
  if (!match) return null;
  const ms = Date.parse(value.length === 10 ? `${value}T00:00:00Z` : value);
  if (!Number.isFinite(ms)) return null;
  const t = new Date(ms);
  // V8 rolls "2026-02-30" over to March 2; a calendar date must name a real day.
  if (value.length === 10 && (t.getUTCMonth() + 1 !== Number(match[2]) || t.getUTCDate() !== Number(match[3]))) return null;
  return { y: t.getUTCFullYear(), m: t.getUTCMonth(), d: t.getUTCDate() };
}

/** "Oct 13", or "Oct 13, 2025" when the year differs from `refYear`; null when not a date. */
export function fmtDay(value: unknown, refYear: number): string | null {
  const t = utcDay(value);
  if (!t) return null;
  const base = `${MONTHS[t.m]} ${t.d}`;
  return t.y === refYear ? base : `${base}, ${t.y}`;
}

/** "Nov 3, 2026 06:50 UTC" for an ISO date-time; null when it is not one. */
export function fmtRunTime(value: unknown): string | null {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value) || value.length > 40) return null;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return null;
  const t = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${MONTHS[t.getUTCMonth()]} ${t.getUTCDate()}, ${t.getUTCFullYear()} ${p(t.getUTCHours())}:${p(t.getUTCMinutes())} UTC`;
}

/** A probability as a percentage with one decimal ("14.2%"), two under 1% ("0.42%"); null when not in 0..1. */
export function fmtPercent(fraction: unknown): string | null {
  if (typeof fraction !== 'number' || !Number.isFinite(fraction) || fraction < 0 || fraction > 1) return null;
  const p = fraction * 100;
  return `${p.toFixed(p >= 1 || p === 0 ? 1 : 2).replace(/\.0+$/, '')}%`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "the default knob (50)", or "the knob (60)" when the page's knob is turned. */
const knobText = (knob: number) => (knob === KNOB_DEFAULT ? `the default knob (${knob})` : `the knob (${knob})`);

/** The strongest exploit-artifact (X) chip that counted, else any X chip that raised the score. */
function strongestX(d: CveDetail): Reason | undefined {
  return d.reasons.find((r) => r.family === 'X' && r.polarity === 'up' && r.points > 0) ?? d.reasons.find((r) => r.family === 'X' && r.polarity === 'up');
}

function artifactPhrase(r: Reason, d: CveDetail): string | null {
  switch (r.id) {
    case 'x.metasploit':
      return 'Metasploit module';
    case 'x.nuclei':
      return 'Nuclei template, scannable at internet scale';
    case 'x.exploitdb':
      return 'Exploit-DB entry';
    case 'epss.high':
    case 'epss.mid': {
      const pct = fmtPercent(d.epss?.score);
      return pct ? `EPSS ${pct} chance of exploitation in 30 days` : null;
    }
    case 'x.poc':
      return `public proof of concept (${plural(d.exploits.poc.vetted, 'vetted repo')})`;
    case 'vendor.functional':
      return 'vendor CVSS says a working exploit exists';
    case 'ssvc.poc':
      return 'CISA SSVC says a proof of concept exists';
    case 'vendor.poc':
      return 'vendor CVSS says a proof of concept exists';
    default:
      return null;
  }
}

/** True when at least one counted chip raised the score (so a Quiet CVE is not "no evidence"). */
export const hasCountedEvidence = (d: CveDetail): boolean => d.reasons.some((r) => r.polarity === 'up' && r.points > 0);

/**
 * The headline and its reason for `tier` at `knob`: "Patch now" + "exploited, KEV due Oct 29",
 * "Likely next" + "Metasploit module", "Watch" + "score 32, below the default knob (50)",
 * "Quiet" + "no evidence yet, and quiet is not safe".
 */
export function verdict(d: CveDetail, tier: Tier, knob: number, refYear: number): { head: string; reason: string } {
  const head = VERDICT_HEADS[tier];
  const score = d.score.value;
  if (tier === 'exploited') {
    if (d.kev) {
      const due = fmtDay(d.kev.due_date, refYear);
      return { head, reason: due ? `exploited, KEV due ${due}` : 'exploited, listed in CISA KEV' };
    }
    if (d.reasons.some((r) => r.id === 'kev.listed')) return { head, reason: 'exploited, listed in CISA KEV' };
    if (d.ssvc?.exploitation === 'active') return { head, reason: 'CISA SSVC says exploitation is active' };
    return { head, reason: 'the vendor reports exploitation' };
  }
  if (tier === 'likely') {
    const x = strongestX(d);
    const phrase = x ? artifactPhrase(x, d) : null;
    return { head, reason: phrase ?? `score ${score} clears ${knobText(knob)}` };
  }
  if (tier === 'watch') return { head, reason: `score ${score}, below ${knobText(knob)}` };
  if (hasCountedEvidence(d)) return { head, reason: `score ${score}, below the watch floor (${WATCH_FLOOR}), and quiet is not safe` };
  return { head, reason: 'no evidence yet, and quiet is not safe' };
}
