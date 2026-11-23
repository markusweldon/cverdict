/**
 * v1/events.json: why verdicts moved, as a rolling log of the last EVENTS_DAYS days.
 *
 * Each event has a stable id (eventKey) and is emitted once. New events come from this run's
 * scored records compared with the previous published tree (the same diffRuns() that changes.json
 * uses), and from dated upstream causes (a CISA KEV dateAdded, an exploited catalog listing, an old
 * CVE's first Exploit-DB entry, Metasploit module or Nuclei template from woke.json):
 *
 *   kev_added          a CISA KEV entry dated in the period, missing from the previous kev.json
 *   catalog_listed     the CVE's first exploited listing (EU KEV, or CIRCL confirmed) is dated in the
 *                      period, and CISA KEV did not list it earlier
 *   vendor_exploited   vendor.exploited or vendor.itw is new in the row's fired chips (Row.r)
 *   tier_up            the tier rose into Likely next or Exploited
 *   fast_lane          fast.lane is new in Row.r
 *   metasploit_module  x.metasploit is new in Row.r, or an old CVE woke up with its first module
 *   nuclei_template    the same for x.nuclei / a woke Nuclei template
 *   exploitdb_entry    the same for x.exploitdb / a woke Exploit-DB entry
 *
 * Folding: a tier_up and another event for the same CVE in one run are one item (the other one,
 * which carries tier_before and tier_after); the tier_up key is still remembered.
 *
 * Dedup: the previous events.json is carried forward, and every key seen is kept for
 * EVENTS_KEY_DAYS in the `events` section of state.json, so an item dropped by the cap is never
 * emitted again while its dated cause is still in the period. `at` never changes.
 *
 * Outages: a scoring source down in this run or the previous one makes the chip and tier
 * comparison start from a baseline (like a score model change), and holds back woke signals dated
 * before the previous run (see `wokeAfter`). KEV and catalog listings are still reported.
 *
 * First runs: without a previous tree there is no diff, so the diff types start from a baseline.
 * Without a previous events.json (first run, or the first deploy of this file), the dated types
 * are backfilled with `at` = their upstream date and `backfill: true`, so old news is never stamped
 * "now". A frozen `--now` filters the same way: nothing is dated after it.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compareEvents, eventRank, TIER_LABEL } from '../../shared/atom';
import {
  EVENT_TYPES,
  SCHEMA_VERSION,
  TIERS,
  type CatalogSnapshot,
  type EventItem,
  type EventsFile,
  type EventType,
  type Row,
  type SourceId,
  type Tier,
  type WokeFile,
} from '../../shared/contract';
import { CVE_ID_RE } from '../../shared/shard';
import type { RunDiff } from './changes';
import { cveOrgUrl, dayLabel, kevSearchUrl } from './score';
import { firstExploitedListing } from './sources/catalogs';
import type { StateSection } from './state';
import type { CatalogListing, KevCatalog, ScoredCve } from './types';
import { DAY_MS, normalizeIso, ymd } from './util/dates';
import { asObject } from './util/json';

export const EVENTS_DAYS = 7;
export const EVENTS_MAX_ITEMS = 1000;
/** Seen keys are remembered this long: longer than the period, so a capped item never returns. */
export const EVENTS_KEY_DAYS = 14;

const isTier = (t: unknown): t is Tier => typeof t === 'string' && (TIERS as readonly string[]).includes(t);
const isType = (t: unknown): t is EventType => typeof t === 'string' && (EVENT_TYPES as readonly string[]).includes(t);
const rank = (t: Tier) => TIERS.indexOf(t);
const passed = (t: Tier) => t === 'exploited' || t === 'likely';
const CATALOG_VIA: readonly SourceId[] = ['eu-kev', 'circl-kev'];
const CATALOG_NAME: Partial<Record<SourceId, string>> = { 'eu-kev': 'EU KEV', 'circl-kev': 'CIRCL' };

/** The stable id of an event. */
export function eventKey(type: EventType, cve: string, opts: { via?: string; tierAfter?: Tier } = {}): string {
  if (type === 'catalog_listed') return `catalog_listed:${opts.via}:${cve}`;
  if (type === 'tier_up') return `tier_up:${cve}:${opts.tierAfter}`;
  return `${type}:${cve}`;
}

/** The id an item must have, from its own fields. */
export const itemKey = (it: Pick<EventItem, 'type' | 'cve' | 'via' | 'tier_after'>) => eventKey(it.type, it.cve, { via: it.via, tierAfter: it.tier_after });

// ── state section ──────────────────────────────────────────────────────────────────────────

/** The `events` section of state.json: every key seen lately, with the run time that first saw it. */
export interface EventsState {
  keys: Record<string, string>;
}

export const EVENTS_SECTION: StateSection<EventsState> = {
  key: 'events',
  version: 1,
  parse(data) {
    const o = asObject(asObject(data)?.keys);
    if (!o) return null;
    const keys: Record<string, string> = {};
    for (const [k, v] of Object.entries(o)) {
      const at = normalizeIso(v);
      if (at && k.length <= 128) keys[k] = at;
    }
    return { keys };
  },
};

// ── catalog snapshots (read by the fast check, scripts/fast-check.sh) ─────────────────────

/** SHA-256 hex of the sorted, unique, upper-cased CVE ids, each followed by "\n". Matches the fast check's jq. */
export function idsHash(ids: Iterable<string>): string {
  const sorted = [...new Set([...ids].map((id) => id.trim().toUpperCase()).filter((id) => CVE_ID_RE.test(id)))].sort();
  return createHash('sha256').update(sorted.map((id) => `${id}\n`).join('')).digest('hex');
}

export function catalogSnapshot(ids: Iterable<string> | null, version: string | null, fetchedAt: string | null): CatalogSnapshot | null {
  if (!ids) return null;
  const list = [...ids];
  if (list.length === 0) return null;
  return { version, count: new Set(list).size, ids_sha256: idsHash(list), fetched_at: fetchedAt };
}

// ── previous file ──────────────────────────────────────────────────────────────────────────

/** A carried-forward item, checked field by field. Null when anything is off. */
export function parseItem(value: unknown): EventItem | null {
  const o = asObject(value);
  if (!o) return null;
  const { id, at, type, cve, vendor, product, tier_before, tier_after, score, title, via, url, detail, backfill } = o;
  if (!isType(type) || typeof cve !== 'string' || !CVE_ID_RE.test(cve) || !isTier(tier_after) || !(tier_before === null || isTier(tier_before))) return null;
  if (typeof at !== 'string' || normalizeIso(at) === null) return null;
  if (typeof vendor !== 'string' || typeof product !== 'string' || typeof title !== 'string' || typeof detail !== 'string' || typeof via !== 'string') return null;
  if (typeof score !== 'number' || !Number.isFinite(score) || !(url === null || typeof url === 'string') || typeof backfill !== 'boolean') return null;
  if (type === 'catalog_listed' && !(CATALOG_VIA as readonly string[]).includes(via)) return null;
  const item: EventItem = { id: String(id), at, type, cve, vendor, product, tier_before, tier_after, score, title, via: via as SourceId, url, detail, backfill };
  return item.id === itemKey(item) ? item : null;
}

/** Items of `<root>/v1/events.json`, or null when there is no usable file (it is then backfilled). */
export function readPreviousEvents(root: string | null): EventItem[] | null {
  if (!root) return null;
  let doc;
  try {
    doc = asObject(JSON.parse(readFileSync(join(root, 'v1', 'events.json'), 'utf8')));
  } catch {
    return null;
  }
  if (!doc || doc.schema_version !== SCHEMA_VERSION || !Array.isArray(doc.items)) return null;
  return doc.items.map(parseItem).filter((i): i is EventItem => i !== null);
}

// ── build ──────────────────────────────────────────────────────────────────────────────────

export interface EventsInput {
  now: Date;
  /** This run's kept records, by id. */
  byId: ReadonlyMap<string, ScoredCve>;
  /** Rows of those records, by id (vendor and product come from here). */
  rows: ReadonlyMap<string, Row>;
  /** This run against the previous index (diffRuns), or null on a first run. */
  diff: RunDiff | null;
  /**
   * Why the chip and tier comparison starts from a baseline this run, e.g. the previous run used
   * another score model: its moves are the model's, not new evidence. Null to compare as usual.
   */
  baseline?: string | null;
  /**
   * When set (an ISO instant, the previous run's time), woke.json may list CVEs it would normally
   * leave out, because a source was down or a check was skipped: only woke signals dated after it
   * count, and the others are not remembered, so a healthy run can still report them.
   */
  wokeAfter?: string | null;
  /** Items of the previous events.json, or null when there was none. */
  previous: EventItem[] | null;
  previousState: EventsState | null;
  kev: KevCatalog;
  catalogs?: ReadonlyMap<string, CatalogListing[]>;
  woke: WokeFile;
  snapshots: EventsFile['catalogs'];
}

export interface EventsOutput {
  file: EventsFile;
  state: EventsState;
  /** Events first emitted by this run. */
  added: EventItem[];
  notes: string[];
}

interface Candidate {
  key: string;
  type: EventType;
  cve: string;
  at: string;
  backfill: boolean;
  tierBefore: Tier | null;
  phrase: string;
  via: SourceId;
  url: string | null;
  detail: string;
}

const WOKE_TYPES: Partial<Record<string, EventType>> = { metasploit: 'metasploit_module', nuclei: 'nuclei_template', exploitdb: 'exploitdb_entry' };
const CHIP_TYPES: readonly [string, EventType, string][] = [
  ['vendor.exploited', 'vendor_exploited', 'vendor reports exploitation'],
  ['vendor.itw', 'vendor_exploited', 'vendor reports exploitation'],
  ['fast.lane', 'fast_lane', 'fast lane'],
  ['x.metasploit', 'metasploit_module', 'Metasploit module'],
  ['x.nuclei', 'nuclei_template', 'Nuclei template'],
  ['x.exploitdb', 'exploitdb_entry', 'Exploit-DB entry'],
];
const WOKE_PHRASE: Record<string, string> = { metasploit_module: 'Metasploit module', nuclei_template: 'Nuclei template', exploitdb_entry: 'Exploit-DB entry' };

const sentence = (s: string) => {
  const t = s.trim().replace(/[.\s]+$/, '');
  return t ? `${t[0].toUpperCase()}${t.slice(1)}.` : '';
};

/** The labels of `ids` among a record's reasons, strongest first, joined for a sentence. */
function chipLabels(s: ScoredCve | undefined, ids: readonly string[], max = 3): string[] {
  if (!s) return [];
  return s.reasons
    .filter((r) => ids.includes(r.id) && r.polarity === 'up')
    .sort((a, b) => b.points - a.points)
    .slice(0, max)
    .map((r) => r.label);
}

export function buildEvents(input: EventsInput): EventsOutput {
  const { now, byId, rows, diff, previous, kev, catalogs, woke } = input;
  const nowMs = now.getTime();
  // Whole seconds, like the backfilled dates, so `at` strings compare in time order.
  const nowIso = now.toISOString().replace(/\.\d+Z$/, 'Z');
  const cutoffMs = nowMs - EVENTS_DAYS * DAY_MS;
  const today = ymd(now);
  const sinceDay = ymd(new Date(cutoffMs));
  const inPeriod = (iso: string) => {
    const t = Date.parse(iso);
    return t >= cutoffMs && t <= nowMs;
  };
  const backfill = previous === null;
  const notes: string[] = [];

  const prevKeys = input.previousState?.keys ?? {};
  const seen = new Set<string>([...Object.keys(prevKeys), ...(previous ?? []).map((i) => i.id)]);
  const candidates: Candidate[] = [];
  /** Keys that were looked at this run and must be remembered, emitted or not. */
  const touched = new Set<string>();
  const prevTier = new Map<string, Tier>();
  for (const p of diff?.pairs ?? []) if (p.prev) prevTier.set(p.cur.id, p.prev.tier);

  const push = (c: Omit<Candidate, 'tierBefore'>) => {
    touched.add(c.key);
    if (!byId.has(c.cve) || !rows.has(c.cve)) return;
    candidates.push({ ...c, tierBefore: prevTier.get(c.cve) ?? null });
  };
  /** A dated cause: now when a diff saw it arrive, else (backfill) its own date, when in the period. */
  const dated = (date: string): { at: string; backfill: boolean } | null => {
    if (!backfill) return { at: nowIso, backfill: false };
    const at = normalizeIso(date);
    return at && inPeriod(at) ? { at: at.replace(/\.\d+Z$/, 'Z'), backfill: true } : null;
  };

  // CISA KEV additions dated in the period.
  for (const k of kev.entries.values()) {
    if (k.dateAdded < sinceDay || k.dateAdded > today) continue;
    const key = eventKey('kev_added', k.cveID);
    const isNew = diff?.previousKev ? !diff.previousKev.has(k.cveID) : false;
    const when = isNew ? { at: nowIso, backfill: false } : backfill ? dated(k.dateAdded) : null;
    if (!when) {
      if (backfill) touched.add(key);
      continue;
    }
    const ransomware = k.knownRansomwareCampaignUse?.trim() || 'Unknown';
    push({ key, type: 'kev_added', cve: k.cveID, ...when, phrase: 'added to CISA KEV', via: 'kev', url: kevSearchUrl(k.cveID), detail: `Added ${dayLabel(k.dateAdded, now)}, due ${dayLabel(k.dueDate, now)}. Known ransomware use: ${ransomware}.` });
  }

  // First exploited listings in EU KEV or CIRCL dated in the period, unless CISA KEV listed the CVE before.
  for (const [id, list] of catalogs ?? []) {
    const l = firstExploitedListing(list, today);
    if (!l || l.added < sinceDay) continue;
    const cisa = kev.entries.get(id)?.dateAdded;
    if (cisa && cisa < l.added) continue;
    const key = eventKey('catalog_listed', id, { via: l.catalog });
    if (seen.has(key)) {
      touched.add(key);
      continue;
    }
    const when = dated(l.added);
    if (!when) {
      touched.add(key);
      continue;
    }
    const name = CATALOG_NAME[l.catalog] ?? l.catalog;
    const detail = l.catalog === 'eu-kev' ? `EU KEV lists it as exploited, added ${dayLabel(l.added, now)}.` : `CIRCL lists it as confirmed exploited, added ${dayLabel(l.added, now)}.`;
    push({ key, type: 'catalog_listed', cve: id, ...when, phrase: `listed as exploited by ${name}`, via: l.catalog as SourceId, url: l.url ?? null, detail });
  }

  // Moves and new chips since the previous index.
  if (input.baseline && diff) notes.push(`chip and tier comparison starts from a baseline: ${input.baseline}`);
  for (const { prev, cur, published } of input.baseline ? [] : (diff?.pairs ?? [])) {
    const s = byId.get(cur.id);
    // Chips are only new when the previous row had a chip list to compare, or the CVE is new.
    const before = prev ? (Array.isArray(prev.r) ? new Set(prev.r) : null) : published ? new Set<string>() : null;
    const added = before ? cur.r.filter((c) => !before.has(c)) : [];
    if (before) {
      const done = new Set<EventType>();
      for (const [chip, type, phrase] of CHIP_TYPES) {
        if (!added.includes(chip) || done.has(type)) continue;
        done.add(type);
        const reason = s?.reasons.find((r) => r.id === chip);
        const via: SourceId = reason?.source ?? 'computed';
        const url = reason?.url ?? (type === 'vendor_exploited' ? cveOrgUrl(cur.id) : null);
        const lead = published ? `New CVE, published ${dayLabel(cur.pub, now)}. ` : '';
        push({ key: eventKey(type, cur.id), type, cve: cur.id, at: nowIso, backfill: false, phrase, via, url, detail: `${lead}${sentence(reason?.label ?? phrase)}` });
      }
    }
    if (passed(cur.tier) && (!prev || rank(cur.tier) < rank(prev.tier))) {
      const labels = chipLabels(s, added);
      const lead = !prev && published ? `New CVE, published ${dayLabel(cur.pub, now)}.` : prev ? `Rose from ${TIER_LABEL[prev.tier]} to ${TIER_LABEL[cur.tier]}.` : `Now ${TIER_LABEL[cur.tier]}.`;
      const why = labels.length ? ` New evidence: ${labels.join('; ')}.` : ` Score ${prev ? `${prev.s} to ` : ''}${cur.s}.`;
      push({ key: eventKey('tier_up', cur.id, { tierAfter: cur.tier }), type: 'tier_up', cve: cur.id, at: nowIso, backfill: false, phrase: `now ${TIER_LABEL[cur.tier]}`, via: 'computed', url: null, detail: `${lead}${why}` });
    }
  }

  // Old CVEs whose first exploit artifact arrived in the period (woke.json).
  const wokeAfterMs = input.wokeAfter ? Date.parse(input.wokeAfter) : null;
  let wokeHeld = 0;
  for (const it of woke.items) {
    for (const sig of it.signals) {
      const type = WOKE_TYPES[sig.kind];
      if (!type) continue;
      const at = normalizeIso(sig.at);
      if (!at || !inPeriod(at)) continue;
      const key = eventKey(type, it.id);
      if (seen.has(key)) {
        touched.add(key);
        continue;
      }
      if (wokeAfterMs !== null && !(Date.parse(at) > wokeAfterMs)) {
        wokeHeld++;
        continue;
      }
      const when = dated(sig.at);
      if (!when) {
        touched.add(key);
        continue;
      }
      push({ key, type, cve: it.id, ...when, phrase: WOKE_PHRASE[type], via: sig.source, url: sig.url, detail: `Published ${dayLabel(it.row.pub, now)}. ${sentence(sig.label)}` });
    }
  }

  if (wokeHeld) notes.push(`${wokeHeld} woke signals dated before the previous run held back: a source was down or a check skipped`);

  // One candidate per key (the first wins), never one already seen.
  const fresh = new Map<string, Candidate>();
  for (const c of candidates) if (!seen.has(c.key) && !fresh.has(c.key)) fresh.set(c.key, c);
  // Folding: a tier move rides on another event for the same CVE in this run.
  const otherByCve = new Set([...fresh.values()].filter((c) => c.type !== 'tier_up').map((c) => c.cve));
  let folded = 0;
  for (const [key, c] of fresh) {
    if (c.type === 'tier_up' && otherByCve.has(c.cve)) {
      fresh.delete(key);
      folded++;
    }
  }

  const added: EventItem[] = [...fresh.values()].map((c) => {
    const s = byId.get(c.cve)!;
    const row = rows.get(c.cve)!;
    // "Gitblit Gitblit" reads as "Gitblit"; "Fortinet FortiOS" stays.
    const product = (row.p.toLowerCase().startsWith(row.v.toLowerCase()) ? row.p : `${row.v} ${row.p}`).replace(/\s+/g, ' ').trim();
    return {
      id: c.key,
      at: c.at,
      type: c.type,
      cve: c.cve,
      vendor: row.v,
      product: row.p,
      tier_before: c.tierBefore,
      tier_after: s.tier,
      score: s.score,
      title: [c.cve, product, c.phrase].filter(Boolean).join(' · '),
      via: c.via,
      url: c.url,
      detail: c.detail,
      backfill: c.backfill,
    };
  });

  const carried = (previous ?? []).filter((i) => inPeriod(i.at));
  const byKey = new Map<string, EventItem>();
  for (const it of [...carried, ...added]) if (!byKey.has(it.id)) byKey.set(it.id, it);
  const all = [...byKey.values()].sort(compareEvents);
  // Over the cap the lowest-priority, oldest items go first; the file stays newest first.
  const keep = new Set([...all].sort((a, b) => eventRank(a) - eventRank(b) || compareEvents(a, b)).slice(0, EVENTS_MAX_ITEMS));
  const items = all.filter((i) => keep.has(i));
  if (all.length > items.length) notes.push(`${all.length - items.length} events over the cap of ${EVENTS_MAX_ITEMS} dropped`);

  // Remember every key seen lately: carried, emitted, folded, and the dated ones a backfill skipped.
  const keyCutoff = nowMs - EVENTS_KEY_DAYS * DAY_MS;
  const keys: Record<string, string> = {};
  for (const [k, at] of Object.entries(prevKeys)) if (Date.parse(at) >= keyCutoff) keys[k] = at;
  for (const it of items) keys[it.id] ??= it.at;
  for (const k of touched) keys[k] ??= nowIso;
  const sortedKeys = Object.fromEntries(Object.entries(keys).sort(([a], [b]) => a.localeCompare(b)));

  notes.push(
    `${added.length} new (${backfill ? 'backfilled from upstream dates, ' : ''}${folded} tier moves folded into another event), ${items.length} in ${EVENTS_DAYS} days, ${Object.keys(sortedKeys).length} keys remembered`,
  );
  return {
    file: {
      schema_version: SCHEMA_VERSION,
      generated_at: nowIso,
      previous_at: diff?.previousAt ?? null,
      days: EVENTS_DAYS,
      max_items: EVENTS_MAX_ITEMS,
      catalogs: input.snapshots,
      items,
    },
    state: { keys: sortedKeys },
    added: added.sort(compareEvents),
    notes,
  };
}
