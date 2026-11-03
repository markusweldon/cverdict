/** Pure helpers for the "Woke up" feed: labels, filters, weeks and the one-line summary. */
import { TIERS, WAKE_KINDS, type WakeKind, type WakeSignal, type WokeFile, type WokeInfo, type WokeItem } from '../../shared/contract';
import { DAY_MS, fmtDate, toMs } from './format';

/** Short names for filter buttons and counts. */
export const WAKE_KIND_LABEL: Readonly<Record<WakeKind, string>> = {
  kev: 'CISA KEV',
  exploitdb: 'Exploit-DB',
  metasploit: 'Metasploit',
  nuclei: 'Nuclei',
  poc: 'PoC repo',
  epss: 'EPSS jump',
};

/** The kinds the pipeline can only date by first sight, in the words of the tracking note. */
const FIRST_SEEN_NAMES: Readonly<Record<keyof WokeFile['tracking'], string>> = {
  metasploit: 'Metasploit modules',
  nuclei: 'Nuclei templates',
  epss: 'EPSS jumps',
};

export const atMs = (at: string): number => toMs(at);
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

export function isWakeKind(v: string | null): v is WakeKind {
  return v !== null && (WAKE_KINDS as readonly string[]).includes(v);
}

/** Items with a signal of `kind` (all items when null). */
export function byKind(items: readonly WokeItem[], kind: WakeKind | null): WokeItem[] {
  return kind ? items.filter((i) => i.signals.some((s) => s.kind === kind)) : [...items];
}

/**
 * Items whose newest signal is at most `days` before `now`. A date-only `at` (KEV, Exploit-DB,
 * EPSS) is a calendar day, so it counts when any part of that day is inside, as in the pipeline:
 * a KEV listing dated on the boundary day most likely came after the cut.
 */
export function wokeWithin(items: readonly WokeItem[], now: number, days: number): WokeItem[] {
  const cut = now - days * DAY_MS;
  const cutDay = new Date(cut).toISOString().slice(0, 10);
  return items.filter((i) => (DATE_ONLY.test(i.at) ? i.at >= cutDay : atMs(i.at) >= cut));
}

/** Most urgent first (tier at the knob), then newest wake: for the short list on Today. */
export function mostUrgent(items: readonly WokeItem[], tierOf: (i: WokeItem) => (typeof TIERS)[number]): WokeItem[] {
  return [...items].sort((a, b) => TIERS.indexOf(tierOf(a)) - TIERS.indexOf(tierOf(b)) || atMs(b.at) - atMs(a.at) || a.id.localeCompare(b.id));
}

/** "Woke up Oct 30: added to CISA KEV." or, with several signals, "Woke up Oct 12: …. Oct 30: …." */
export function wakeSentence(info: WokeInfo, refYear?: number): string {
  return `Woke up ${info.signals.map((s) => `${fmtDate(s.at, refYear)}: ${s.label}`).join('. ')}.`;
}

/** Tooltip for a signal dated by first sight. */
export function firstSeenTip(s: WakeSignal): string | undefined {
  if (!s.first_seen) return undefined;
  return s.kind === 'epss'
    ? 'Two daily EPSS files cannot say which day the score rose, so this is the day we first saw the rise.'
    : 'The source gives no date, so this is the day we first saw it.';
}

/** "Metasploit modules, Nuclei templates and EPSS jumps" tracked since …, and the kinds not tracked yet. */
export function trackingNote(tracking: WokeFile['tracking']): { since: string | null; tracked: string[]; untracked: string[] } {
  const keys = Object.keys(FIRST_SEEN_NAMES) as (keyof WokeFile['tracking'])[];
  const tracked = keys.filter((k) => tracking[k] !== null);
  const since = tracked.map((k) => tracking[k]!).sort()[tracked.length - 1] ?? null;
  return { since, tracked: tracked.map((k) => FIRST_SEEN_NAMES[k]), untracked: keys.filter((k) => tracking[k] === null).map((k) => FIRST_SEEN_NAMES[k]) };
}

/** "a, b and c". */
export function listing(names: readonly string[]): string {
  return names.length <= 1 ? (names[0] ?? '') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

/** Monday (UTC) of the week containing `at`, as YYYY-MM-DD. */
export function weekOf(at: string): string {
  const t = atMs(at);
  const day = Date.UTC(new Date(t).getUTCFullYear(), new Date(t).getUTCMonth(), new Date(t).getUTCDate());
  const dow = (new Date(day).getUTCDay() + 6) % 7;
  return new Date(day - dow * DAY_MS).toISOString().slice(0, 10);
}

/** Items grouped by the week of their newest signal, newest week first (order kept inside). */
export function byWeek(items: readonly WokeItem[]): [string, WokeItem[]][] {
  const m = new Map<string, WokeItem[]>();
  for (const i of items) {
    const w = weekOf(i.at);
    const list = m.get(w);
    if (list) list.push(i);
    else m.set(w, [i]);
  }
  return [...m.entries()].sort((a, b) => b[0].localeCompare(a[0]));
}
