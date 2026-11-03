/**
 * "Woke up": CVEs published before the window that gained exploitation evidence in the last
 * WAKE_DAYS days. The 30-day window cannot see them, yet a large share of KEV additions are
 * years old.
 *
 * Two phases:
 *   1. detectWakes() runs during ingest on the full source indexes (before the CVE List pass ends),
 *      so every candidate ID is known in time to be ingested and scored like a KEV record outside
 *      the window. It also returns the new carry-forward state.
 *   2. buildWoke() runs on the scored records: it keeps candidates published before the window
 *      start and produces woke.json plus the `woke` field of their details.
 *
 * Signals, each "first of its kind" for the CVE so a busy old CVE does not wake up every week:
 *   kev        CISA KEV dateAdded in the period (dated).
 *   exploitdb  the CVE's first Exploit-DB entry was added in the period (date_added, dated).
 *   poc        the CVE's first vetted PoC repo was created in the period (created_at, dated;
 *              same vetting rule as scoring).
 *   metasploit the CVE's first Metasploit module appeared (undated upstream: mod_time is a
 *              modification time, so the first run that saw it is the date).
 *   nuclei     the CVE's first Nuclei template appeared (undated upstream, as above).
 *   epss       EPSS ≥ EPSS_JUMP_MIN and ≥ EPSS_JUMP_FACTOR × its score WAKE_DAYS earlier. Two files
 *              cannot say on which day the jump happened, so it is dated by the score date of
 *              the run that first saw it, which makes it a first-seen kind too.
 * First-seen kinds need state from the previous run. Without it, everything present counts as
 * already known (a baseline) and tracking starts now, so a first run never floods the feed with
 * old news dated today.
 *
 * A CVE that was already in CISA KEV before the period never "wakes up": it was awake already.
 * Evidence only counts when it arrived after the CVE had left the window (published more than
 * the window's length earlier), so nothing joins the feed merely by ageing out of the window.
 */
import {
  SCHEMA_VERSION,
  WAKE_KINDS,
  type SourceId,
  type WakeKind,
  type WakeSignal,
  type WokeFile,
  type WokeInfo,
  type WokeItem,
} from '../../shared/contract';
import { toRow } from './rows';
import { epssUrl, formatPercent, isVettedPoc, kevSearchUrl, pocIndexUrl, utcDay } from './score';
import type { StateSection } from './state';
import type { EpssTable, ExploitDbData, ExploitIndex, KevCatalog, PocRepo, ScoredCve } from './types';
import { addDays, DAY_MS, normalizeIso, normalizeYmd, ymd } from './util/dates';
import { asNumber, asObject, asString } from './util/json';
import { normalizeCveId } from './util/text';

/** How far back a wake signal counts. */
export const WAKE_DAYS = 30;
/** EPSS jump: the new score must be at least this… */
export const EPSS_JUMP_MIN = 0.1;
/** …and at least this many times the score WAKE_DAYS earlier. */
export const EPSS_JUMP_FACTOR = 3;
/**
 * First-seen times are only trusted when the previous state is at most this old. After a longer
 * gap (the pipeline was down), an artifact first seen now may be weeks old, so undated tracking
 * restarts from a fresh baseline instead of dating it wrongly.
 */
export const MAX_STATE_GAP_HOURS = 48;
/** woke.json keeps at most this many CVEs (newest first). */
export const WOKE_MAX_ITEMS = 500;

export type UndatedKind = 'metasploit' | 'nuclei';
export const UNDATED_KINDS: readonly UndatedKind[] = ['metasploit', 'nuclei'];

/** EPSS jump tracking. */
export interface EpssTrack {
  /** When tracking started (the baseline run). */
  since: string;
  /**
   * Jumps seen within WAKE_DAYS, by CVE: the score date when first seen, the scores WAKE_DAYS
   * earlier and then. `baseline` jumps were already there when tracking started and are not shown.
   */
  jumps: Record<string, { at: string; from: number; to: number; baseline: boolean }>;
}

/** First-seen tracking for one undated source. */
export interface ArtifactTrack {
  /** When tracking started (the baseline run). */
  since: string;
  /** Every CVE ID that has had an artifact of this kind since tracking started, sorted. */
  known: string[];
  /** CVEs whose first artifact appeared after `since`, while still within WAKE_DAYS. */
  fresh: Record<string, { at: string; url: string | null }>;
}

/** The `woke` section of state.json. */
export interface WokeState {
  metasploit: ArtifactTrack | null;
  nuclei: ArtifactTrack | null;
  epss: EpssTrack | null;
}

export const EMPTY_WOKE_STATE: WokeState = { metasploit: null, nuclei: null, epss: null };

function parseTrack(value: unknown): ArtifactTrack | null {
  const o = asObject(value);
  const since = normalizeIso(o?.since);
  if (!o || !since || !Array.isArray(o.known)) return null;
  const known = o.known.map(normalizeCveId).filter((id): id is string => id !== null);
  const fresh: ArtifactTrack['fresh'] = {};
  for (const [key, v] of Object.entries(asObject(o.fresh) ?? {})) {
    const id = normalizeCveId(key);
    const e = asObject(v);
    const at = normalizeIso(e?.at);
    const url = asString(e?.url);
    if (id && at) fresh[id] = { at, url: url && /^https:\/\//.test(url) ? url : null };
  }
  return { since, known, fresh };
}

function parseEpssTrack(value: unknown): EpssTrack | null {
  const o = asObject(value);
  const since = normalizeIso(o?.since);
  if (!o || !since) return null;
  const jumps: EpssTrack['jumps'] = {};
  for (const [key, v] of Object.entries(asObject(o.jumps) ?? {})) {
    const id = normalizeCveId(key);
    const e = asObject(v);
    const at = normalizeYmd(e?.at);
    const from = asNumber(e?.from);
    const to = asNumber(e?.to);
    if (id && at && from !== null && to !== null && from >= 0 && to <= 1) jumps[id] = { at, from, to, baseline: e?.baseline === true };
  }
  return { since, jumps };
}

export const WOKE_SECTION: StateSection<WokeState> = {
  key: 'woke',
  version: 1,
  parse(data) {
    const o = asObject(data);
    if (!o) return null;
    return { metasploit: parseTrack(o.metasploit), nuclei: parseTrack(o.nuclei), epss: parseEpssTrack(o.epss) };
  },
};

export interface WakeInput {
  now: Date;
  /** Null when the source is unavailable this run (then its signals are skipped, not "none"). */
  kev: KevCatalog | null;
  exploitdb: ExploitDbData | null;
  metasploit: ExploitIndex['metasploit'] | null;
  nuclei: ExploitIndex['nuclei'] | null;
  /** Every PoC file, by CVE ID. */
  poc: ReadonlyMap<string, PocRepo[]> | null;
  epss: EpssTable | null;
  /** The EPSS scores WAKE_DAYS before `epss.scoreDate`, or null with the reason. */
  epssPast: EpssTable | null;
  epssPastError: string | null;
  /** The previous run's woke state (null: none, or not usable). */
  previous: WokeState | null;
  /** When the previous state was written. */
  previousAt: string | null;
}

export interface WakeDetection {
  /** Every CVE with a signal in the period, whatever its publication date (buildWoke filters). */
  signals: Map<string, WakeSignal[]>;
  state: WokeState;
  tracking: WokeFile['tracking'];
  skipped: WokeFile['skipped'];
  /** Lines for the run log. */
  notes: string[];
}

const add = (map: Map<string, WakeSignal[]>, id: string, s: WakeSignal) => {
  const list = map.get(id);
  if (list) list.push(s);
  else map.set(id, [s]);
};

const signal = (kind: WakeKind, at: string, label: string, source: SourceId, url: string | null, firstSeen = false): WakeSignal => ({
  kind,
  at,
  first_seen: firstSeen,
  label,
  source,
  url,
});

/** Phase 1: every wake signal from the full source indexes, plus the next state. Pure. */
export function detectWakes(input: WakeInput): WakeDetection {
  const { now } = input;
  const nowIso = now.toISOString();
  const sinceMs = now.getTime() - WAKE_DAYS * DAY_MS;
  const sinceDay = ymd(new Date(sinceMs));
  const today = ymd(now);
  const inPeriodDay = (d: string) => d >= sinceDay && d <= today;
  const inPeriodTime = (iso: string) => {
    const t = Date.parse(iso);
    return t >= sinceMs && t <= now.getTime();
  };
  const signals = new Map<string, WakeSignal[]>();
  const skipped: WokeFile['skipped'] = [];
  const notes: string[] = [];
  const unavailable = (kind: WakeKind, what: string) => skipped.push({ kind, reason: `${what} could not be loaded this run` });

  // KEV: dateAdded within the period.
  if (input.kev) {
    for (const k of input.kev.entries.values()) {
      if (inPeriodDay(k.dateAdded)) add(signals, k.cveID, signal('kev', k.dateAdded, 'added to CISA KEV', 'kev', kevSearchUrl(k.cveID)));
    }
  } else unavailable('kev', 'The CISA KEV catalog');

  // Exploit-DB: the CVE's first entry was added within the period.
  if (input.exploitdb) {
    for (const [id, first] of input.exploitdb.firstAdded) {
      if (inPeriodDay(first.date)) add(signals, id, signal('exploitdb', first.date, `first Exploit-DB entry (EDB-${first.id})`, 'exploitdb', first.url));
    }
  } else unavailable('exploitdb', 'Exploit-DB');

  // PoC: the CVE's first vetted repo was created within the period.
  if (input.poc) {
    for (const [id, repos] of input.poc) {
      let first: PocRepo | null = null;
      for (const r of repos) {
        if (r.fork || !isVettedPoc(r, now)) continue;
        if (!first || Date.parse(r.created) < Date.parse(first.created)) first = r;
      }
      if (first && inPeriodTime(first.created)) add(signals, id, signal('poc', first.created, 'first PoC repo on GitHub (unverified)', 'poc-github', pocIndexUrl(id)));
    }
  } else unavailable('poc', 'PoC-in-GitHub');

  // Undated artifacts: first-seen tracking against the previous state. After a long gap the
  // previous state is kept (what it dated stays true) but new artifacts join the baseline.
  const prev = input.previous ?? EMPTY_WOKE_STATE;
  const gapHours = input.previousAt ? (now.getTime() - Date.parse(input.previousAt)) / 3_600_000 : Infinity;
  const gap = input.previous !== null && !(gapHours >= 0 && gapHours <= MAX_STATE_GAP_HOURS);
  if (gap) notes.push(`previous state is ${Number.isFinite(gapHours) ? `${Math.round(gapHours)} h` : 'of unknown'} old; first-seen tracking restarts`);
  const state: WokeState = { metasploit: null, nuclei: null, epss: null };
  const tracking: WokeFile['tracking'] = { metasploit: null, nuclei: null, epss: null };
  const sources: Record<UndatedKind, { map: Map<string, { url: string }[]> | null; label: string; source: SourceId; name: string }> = {
    metasploit: { map: input.metasploit, label: 'first Metasploit module', source: 'metasploit', name: 'Metasploit' },
    nuclei: { map: input.nuclei, label: 'first Nuclei template', source: 'nuclei', name: 'Nuclei templates' },
  };
  for (const kind of UNDATED_KINDS) {
    const { map, label, source, name } = sources[kind];
    const before = prev[kind];
    let track: ArtifactTrack | null;
    if (!map) {
      // Keep what we knew; detect nothing new until the source is back.
      track = before ? { ...before, fresh: { ...before.fresh } } : null;
      unavailable(kind, name);
    } else if (!before || gap) {
      track = { since: nowIso, known: [...new Set([...(before?.known ?? []), ...map.keys()])].sort(), fresh: { ...before?.fresh } };
      notes.push(`${kind}: baseline of ${track.known.length} CVEs; tracking starts now`);
    } else {
      const known = new Set(before.known);
      const fresh = { ...before.fresh };
      let found = 0;
      for (const [id, list] of map) {
        if (known.has(id)) continue;
        known.add(id);
        fresh[id] = { at: nowIso, url: list[0]?.url ?? null };
        found++;
      }
      track = { since: before.since, known: [...known].sort(), fresh };
      if (found) notes.push(`${kind}: ${found} CVEs with a first artifact since the previous run`);
    }
    if (track) {
      for (const [id, e] of Object.entries(track.fresh)) if (!inPeriodTime(e.at)) delete track.fresh[id];
      for (const [id, e] of Object.entries(track.fresh)) add(signals, id, signal(kind, e.at, label, source, e.url, true));
    }
    state[kind] = track;
    tracking[kind] = track?.since ?? null;
  }

  // EPSS jumps, kept in state with the score date they were first seen.
  const beforeEpss = prev.epss;
  const scoreDate = input.epss?.scoreDate ?? null;
  let epss: EpssTrack | null = beforeEpss ? { since: beforeEpss.since, jumps: {} } : null;
  for (const [id, e] of Object.entries(beforeEpss?.jumps ?? {})) if (inPeriodDay(e.at)) epss!.jumps[id] = e;
  if (!input.epss || !scoreDate) unavailable('epss', 'The current EPSS scores');
  else if (!input.epssPast) skipped.push({ kind: 'epss', reason: `EPSS scores from ${WAKE_DAYS} days earlier could not be loaded (${input.epssPastError ?? 'unknown error'}), so no jumps were checked` });
  else {
    const baseline = epss === null || gap;
    epss = { since: baseline ? nowIso : epss!.since, jumps: epss?.jumps ?? {} };
    let found = 0;
    for (const [id, cur] of input.epss.scores) {
      if (cur.epss < EPSS_JUMP_MIN || epss.jumps[id]) continue;
      const old = input.epssPast.scores.get(id);
      // No score back then is unknown history, not a jump.
      if (!old || cur.epss < EPSS_JUMP_FACTOR * old.epss) continue;
      epss.jumps[id] = { at: scoreDate, from: old.epss, to: cur.epss, baseline };
      found++;
    }
    notes.push(baseline ? `epss: baseline of ${found} jumps against ${input.epssPast.scoreDate}; tracking starts now` : `epss: ${found} new jumps against ${input.epssPast.scoreDate}`);
  }
  state.epss = epss;
  tracking.epss = epss?.since ?? null;
  for (const [id, e] of Object.entries(epss?.jumps ?? {})) {
    if (e.baseline) continue;
    add(signals, id, signal('epss', e.at, `EPSS rose from ${formatPercent(e.from)} to ${formatPercent(e.to)} in ${WAKE_DAYS} days`, 'epss', `${epssUrl(id)}&scope=time-series`, true));
  }

  for (const list of signals.values()) list.sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || WAKE_KINDS.indexOf(a.kind) - WAKE_KINDS.indexOf(b.kind));
  return { signals, state, tracking, skipped, notes };
}

/** What detectWakes would leave when it cannot run: the previous state unchanged, every signal skipped. */
export function failedWakeDetection(previous: WokeState | null, reason: string): WakeDetection {
  const state = previous ?? EMPTY_WOKE_STATE;
  return {
    signals: new Map(),
    state,
    tracking: { metasploit: state.metasploit?.since ?? null, nuclei: state.nuclei?.since ?? null, epss: state.epss?.since ?? null },
    skipped: WAKE_KINDS.map((kind) => ({ kind, reason: `wake detection failed: ${reason}` })),
    notes: [],
  };
}

/** The date WAKE_DAYS before an EPSS score date, and the day before it (in case one is missing). */
export function epssPastDates(scoreDate: string): string[] {
  const d = new Date(`${scoreDate}T00:00:00Z`);
  return [ymd(addDays(d, -WAKE_DAYS)), ymd(addDays(d, -WAKE_DAYS - 1))];
}

export interface WokeOutput {
  file: WokeFile;
  /** Woke CVE IDs (their details carry `woke`). */
  ids: Set<string>;
}

/**
 * Phase 2: keep scored candidates published before `windowStart`, set their `woke` field
 * (mutates the ScoredCve, so call before building details) and build woke.json.
 */
export function buildWoke(scored: readonly ScoredCve[], wake: WakeDetection, now: Date, windowStart: Date): WokeOutput {
  const sinceDay = ymd(new Date(now.getTime() - WAKE_DAYS * DAY_MS));
  const items: (WokeItem & { s: ScoredCve })[] = [];
  const counts = Object.fromEntries(WAKE_KINDS.map((k) => [k, 0])) as Record<WakeKind, number>;
  const windowMs = now.getTime() - windowStart.getTime();
  for (const s of scored) {
    const published = Date.parse(s.cve.published);
    if (s.cve.inWindow || published >= windowStart.getTime()) continue;
    // Only evidence that arrived once the CVE was already older than the window: a CVE that got a
    // KEV listing at 25 days old was in the normal views then, and must not "wake up" days later
    // just because it aged out of the window.
    const leftWindow = ymd(new Date(published + windowMs));
    const signals = (wake.signals.get(s.cve.id) ?? []).filter((x) => utcDay(x.at) >= leftWindow);
    if (!signals.length) continue;
    // Already in KEV before the period: it was awake already, newer evidence is not news.
    const listed = normalizeYmd(s.kev?.date_added ?? s.cve.adpKev?.dateAdded);
    if (listed && listed < sinceDay) continue;
    const info: WokeInfo = { at: signals.reduce((max, x) => (Date.parse(x.at) > Date.parse(max) ? x.at : max), signals[0].at), signals };
    s.woke = info;
    items.push({ id: s.cve.id, ...info, row: toRow(s), s });
  }
  items.sort((a, b) => Date.parse(b.at) - Date.parse(a.at) || b.row.s - a.row.s || a.id.localeCompare(b.id));
  for (const dropped of items.slice(WOKE_MAX_ITEMS)) dropped.s.woke = null;
  const kept: WokeItem[] = items.slice(0, WOKE_MAX_ITEMS).map(({ s: _s, ...item }) => item);
  for (const it of kept) for (const k of new Set(it.signals.map((x) => x.kind))) counts[k]++;
  return {
    file: {
      schema_version: SCHEMA_VERSION,
      generated_at: now.toISOString(),
      since: new Date(now.getTime() - WAKE_DAYS * DAY_MS).toISOString(),
      days: WAKE_DAYS,
      published_before: windowStart.toISOString(),
      tracking: wake.tracking,
      skipped: wake.skipped,
      counts,
      items: kept,
    },
    ids: new Set(kept.map((i) => i.id)),
  };
}
