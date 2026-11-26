/**
 * The MCP tools as plain functions over the published files: (call, args, now) -> result.
 * No SDK imports, so they are unit-tested with a fake fetch. Every result starts with `data`, which
 * names the run and every file the answer came from (McpData in shared/contract.ts).
 */
import {
  KNOB_DEFAULT,
  NON_SCORING_SOURCES,
  SIGNAL_MIN_SCORE,
  TIERS,
  tierFor,
  type BacktestItem,
  type CveDetail,
  type EventItem,
  type EventType,
  type McpChangesResult,
  type McpData,
  type McpDependenciesResult,
  type McpDependencyFinding,
  type McpInventoryItem,
  type McpInventoryName,
  type McpInventoryResult,
  type McpKevDueResult,
  type McpNotFound,
  type McpReceiptsResult,
  type McpRow,
  type McpSearchResult,
  type McpSignalResult,
  type McpVerdict,
  type McpVerdictResult,
  type McpWokeResult,
  type Meta,
  type PackagesFile,
  type ReceiptItem,
  type Row,
  rowsFromTable,
  type Tier,
  type WakeKind,
} from '../../shared/contract';
import { BRAND } from '../../shared/brand';
import { MCP_MSG, VERDICT } from '../../shared/mcp';
import { BASE_POINTS } from '../../shared/model';
import { CVE_ID_RE, shardOf } from '../../shared/shard';
import { slugify } from '../../shared/slug';
import { WATCH_NAME_MAX, matchesName, normalizeName } from '../../shared/watch';
import { realpathSync, statSync } from 'node:fs';
import { basename, isAbsolute, relative, resolve } from 'node:path';
import { mergePackageFiles } from '../../shared/packages';
import type { Group } from '../../site/src/check/match';
import { checkFiles, countByGroup } from '../../cli/src/check';
import { discover, isCheckable } from '../../cli/src/discover';
import { findingUrl } from '../../cli/src/report';
import { DataError, DataUnavailable, parse, type DataCall } from './data';

/** A request the tool cannot answer as asked (isError: true). A filter is never silently dropped. */
export class InputError extends Error {}

export const LIMITS = { ids: 15, detailIds: 5, page: 50, offset: 100_000, queryWords: 8, withinDays: 60, overdueDays: 14, names: 200, nameChars: WATCH_NAME_MAX, perName: 25 } as const;

/** Bytes of JSON check_inventory answers with at most (about 17,000 tokens); the least urgent CVEs are left out to fit. */
export const INVENTORY_BUDGET = 60 * 1024;

const DAY_MS = 86_400_000;
const TITLE_MAX = 160;
/** Pipeline event details run to about 120 characters; a mirror may send more. */
const DETAIL_MAX = 300;

/** UTC date or date-time: anchored, no nested quantifiers; applied after a length cap of 30. */
export const DATE_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?Z)?$/;

/** Milliseconds for a DATE_RE string, or NaN when it does not match or does not exist (2026-02-30). */
export function parseUtc(s: string): number {
  if (s.length > 30 || !DATE_RE.test(s)) return NaN;
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) return NaN;
  const iso = new Date(ms).toISOString();
  if (iso.slice(0, 10) !== s.slice(0, 10) || (s.length > 10 && iso.slice(11, 16) !== s.slice(11, 16))) return NaN;
  return ms;
}

function dateArg(field: string, s: string): number {
  const ms = parseUtc(s);
  if (Number.isNaN(ms)) throw new InputError(MCP_MSG.badDate(field));
  return ms;
}

const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim();
const cut = (s: string, max: number) => (s.length <= max ? s : `${s.slice(0, max - 1).trimEnd()}…`);
const cveOrg = (id: string) => `https://www.cve.org/CVERecord?id=${id}`;

/** Highest score first, then newest, then id: the pipeline's order (byScoreThenNewest). */
const byScore = (a: Row, b: Row) => b.s - a.s || b.pub.localeCompare(a.pub) || a.id.localeCompare(b.id);

export function mcpRow(r: Row, knob: number): McpRow {
  return {
    id: r.id,
    tier: tierFor(r.s, r.x === 1, r.w === 1, knob),
    score: r.s,
    published: r.pub,
    cna: r.cna,
    vendor: r.v,
    product: r.p,
    // The pipeline already caps Row.t at 160 characters; a mirror may not.
    title: cut(oneLine(r.t), TITLE_MAX),
    exploited: r.x === 1,
    weaponized: r.w === 1,
    in_kev: r.k === 1,
    kev_due: r.kd,
    cvss: r.cv,
    epss: r.e,
    chips: r.c,
    batch: r.b,
  };
}

async function dataBlock(call: DataCall, now: number): Promise<McpData> {
  const m: Meta = await call.meta();
  return {
    generated_at: m.generated_at,
    age_hours: Math.max(0, Math.floor((now - Date.parse(m.generated_at)) / 3_600_000)),
    score_model: m.score_model,
    knob_default: m.knob_default,
    window: m.window,
    // Only sources that can change a verdict: osv feeds packages.json alone.
    sources_down: m.sources.filter((s) => !s.ok && !NON_SCORING_SOURCES.has(s.id)).map((s) => s.id),
    sources_stale: m.sources.filter((s) => s.ok && s.stale && !NON_SCORING_SOURCES.has(s.id)).map((s) => s.id),
    files: [...call.files.values()],
    warning: call.warnings.size ? [...call.warnings].join(' ') : null,
  };
}

function page<T>(all: T[], offset = 0, limit: number) {
  const items = all.slice(offset, offset + limit);
  return { total: all.length, offset, next_offset: offset + items.length < all.length ? offset + items.length : null, items };
}

// ── get_verdict ─────────────────────────────────────────────────────────────────────────────

export interface VerdictArgs {
  ids: string[];
  knob?: number;
  detail?: boolean;
}

export function verdictOf(d: CveDetail, knob: number, json: string, detail: boolean): McpVerdict {
  const exploited = d.score.tier === 'exploited';
  const weaponized = d.exploits.metasploit.length > 0 || d.exploits.nuclei.length > 0;
  const tier = tierFor(d.score.value, exploited, weaponized, knob);
  const out: McpVerdict = {
    id: d.id,
    found: true,
    tier,
    verdict: VERDICT[tier],
    knob,
    score: d.score.value,
    score_math: { base: BASE_POINTS, raw: d.score.raw },
    exploited,
    weaponized,
    published: d.published,
    cna: d.cna,
    vendor: d.affected[0]?.vendor ?? '',
    product: d.affected[0]?.product ?? '',
    title: cut(oneLine(d.title || d.description), TITLE_MAX),
    cvss: d.cvss && { score: d.cvss.score, version: d.cvss.version, source: d.cvss.source },
    epss: d.epss && { score: d.epss.score, percentile: d.epss.percentile, date: d.epss.date },
    kev: d.kev && { date_added: d.kev.date_added, due_date: d.kev.due_date, ransomware: d.kev.ransomware },
    reasons: d.reasons.map((r) => ({ id: r.id, label: r.label, points: r.points, polarity: r.polarity, ...(r.url ? { url: r.url } : {}), ...(r.at ? { at: r.at } : {}) })),
    unknowns: d.unknowns,
    woke: d.woke,
    links: { page: `${BRAND.siteUrl}/cve/${d.id}`, json, cve_org: cveOrg(d.id) },
  };
  if (detail) {
    out.detail = { description: d.description, affected: d.affected, cwe: d.cwe, ssvc: d.ssvc, kev: d.kev, epss: d.epss, exploits: d.exploits, tags: d.tags, timeline: d.timeline, references: d.references };
  }
  return out;
}

export async function getVerdict(call: DataCall, a: VerdictArgs, now: number): Promise<McpVerdictResult> {
  const knob = a.knob ?? KNOB_DEFAULT;
  const ids = [...new Set(a.ids.map((s) => s.trim().toUpperCase()))];
  if (ids.length > LIMITS.ids) throw new InputError(`ids takes at most ${LIMITS.ids} IDs.`);
  if (a.detail && ids.length > LIMITS.detailIds) throw new InputError(MCP_MSG.detailTooMany(LIMITS.detailIds));
  const valid = ids.filter((id) => CVE_ID_RE.test(id));
  const shards = await call.shards(valid.map(shardOf));
  const items = ids.map((id): McpVerdict | McpNotFound => {
    if (!CVE_ID_RE.test(id)) return { id, found: false, note: MCP_MSG.notCveId, links: null };
    const { shard, url } = shards.get(shardOf(id))!;
    if (!Object.prototype.hasOwnProperty.call(shard.items, id)) return { id, found: false, note: MCP_MSG.notFound, links: { cve_org: cveOrg(id) } };
    return verdictOf(shard.items[id], knob, url, a.detail === true);
  });
  return { data: await dataBlock(call, now), items };
}

// ── list_signal ─────────────────────────────────────────────────────────────────────────────

export interface SignalArgs {
  tiers?: Tier[];
  knob?: number;
  vendor?: string;
  published_since?: string;
  kev_only?: boolean;
  limit?: number;
  offset?: number;
}

export async function listSignal(call: DataCall, a: SignalArgs, now: number): Promise<McpSignalResult> {
  const knob = a.knob ?? KNOB_DEFAULT;
  const tiers: Tier[] = a.tiers?.length ? [...new Set(a.tiers)] : ['exploited', 'likely'];
  const since = a.published_since === undefined ? null : dateArg('published_since', a.published_since);
  const vendor = a.vendor?.trim().toLowerCase() ?? '';
  // signal.json holds every row with score >= 35 or exploited/weaponized: complete for Exploited
  // and Likely next at a knob of 35 or more. Watch, Quiet and lower knobs need index.json.
  const file = knob >= SIGNAL_MIN_SCORE && tiers.every((t) => t === 'exploited' || t === 'likely') ? 'signal.json' : 'index.json';
  const { rows } = await call.file(file, parse.rows);
  const want = new Set(tiers);
  const all = rows
    .filter(
      (r) =>
        want.has(tierFor(r.s, r.x === 1, r.w === 1, knob)) &&
        (!vendor || `${r.v} ${r.p}`.toLowerCase().includes(vendor)) &&
        (since === null || Date.parse(r.pub) >= since) &&
        (!a.kev_only || r.k === 1),
    )
    .sort(byScore);
  const p = page(all, a.offset, a.limit ?? 25);
  return { data: await dataBlock(call, now), knob, tiers, file, ...p, items: p.items.map((r) => mcpRow(r, knob)) };
}

// ── kev_due ─────────────────────────────────────────────────────────────────────────────────

export interface KevDueArgs {
  within_days?: number;
  overdue_days?: number;
  limit?: number;
  offset?: number;
}

export async function kevDue(call: DataCall, a: KevDueArgs, now: number): Promise<McpKevDueResult> {
  const kev = await call.file('kev.json', parse.kev);
  const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
  const today = day(now);
  const from = day(Date.parse(today) - (a.overdue_days ?? 7) * DAY_MS);
  const to = day(Date.parse(today) + (a.within_days ?? 7) * DAY_MS);
  const due = kev.entries.filter((e) => e.due_date >= from && e.due_date <= to).sort((x, y) => x.due_date.localeCompare(y.due_date) || x.id.localeCompare(y.id));
  // Paged like every other list: kev.json may hold a few hundred entries after a large CISA batch.
  const p = page(due, a.offset, a.limit ?? LIMITS.page);
  const items = p.items.map((e) => ({
    id: e.id,
    vendor: e.vendor,
    product: e.product,
    name: oneLine(e.name),
    date_added: e.date_added,
    due_date: e.due_date,
    days_left: Math.round((Date.parse(e.due_date) - Date.parse(today)) / DAY_MS),
    ransomware: e.ransomware,
    forensic_triage: e.forensic_triage,
    required_action: oneLine(e.required_action),
    score: e.score,
  }));
  return { data: await dataBlock(call, now), today_utc: today, from, to, catalog_version: kev.catalog_version, ...p, items };
}

// ── woke_up ─────────────────────────────────────────────────────────────────────────────────

export interface WokeArgs {
  since?: string;
  kinds?: WakeKind[];
  limit?: number;
  offset?: number;
}

export async function wokeUp(call: DataCall, a: WokeArgs, now: number): Promise<McpWokeResult> {
  const woke = await call.file('woke.json', parse.woke);
  const knob = (await call.meta()).knob_default;
  const sinceMs = a.since === undefined ? Date.parse(woke.generated_at) - 7 * DAY_MS : dateArg('since', a.since);
  const since = new Date(sinceMs).toISOString();
  const sinceDay = since.slice(0, 10);
  const kinds = a.kinds?.length ? new Set(a.kinds) : null;
  // Date-only `at` values compare by UTC day, date-times to the millisecond.
  const after = (at: string) => (at.length === 10 ? at >= sinceDay : Date.parse(at) >= sinceMs);
  const all = woke.items.filter((i) => after(i.at) && (!kinds || i.signals.some((s) => kinds.has(s.kind))));
  const p = page(all, a.offset, a.limit ?? 25);
  return {
    data: await dataBlock(call, now),
    since,
    tracking: woke.tracking,
    skipped: woke.skipped,
    ...p,
    items: p.items.map((i) => ({ ...mcpRow(i.row, knob), woke_at: i.at, signals: i.signals.map((s) => ({ ...s, label: oneLine(s.label) })) })),
  };
}

// ── receipts ────────────────────────────────────────────────────────────────────────────────

export interface ReceiptsArgs {
  id?: string;
}

export async function receipts(call: DataCall, a: ReceiptsArgs, now: number): Promise<McpReceiptsResult> {
  const id = a.id?.trim().toUpperCase();
  if (id !== undefined && !CVE_ID_RE.test(id)) throw new InputError(MCP_MSG.notCveId);
  const r = await call.file('receipts.json', parse.receipts);
  // The per-CVE lists stay out of the summary (the file is about 130 KB); `id` picks one CVE's entries.
  const { items, uncounted, gaps: _gaps, ...forward } = r.forward;
  const b = r.backtest;
  const withRow = <T extends ReceiptItem | BacktestItem>(x: T | undefined) => (x ? { ...x, row: x.row && mcpRow(x.row, r.knob) } : null);
  const out: McpReceiptsResult = {
    data: await dataBlock(call, now),
    page: `${BRAND.siteUrl}/receipts`,
    knob: r.knob,
    definitions: r.definitions,
    forward,
    backtest: b && {
      hindsight: b.hindsight,
      computed_at: b.computed_at,
      score_model: b.score_model ?? null,
      from: b.from,
      to: b.to,
      days: b.days,
      listed: b.listed,
      excluded: b.excluded.map((x) => ({ code: x.code, n: x.ids.length })),
      sets: b.sets,
      volume: b.volume,
      epss_missing: b.epss_missing.length,
      sources_down: b.sources_down ?? [],
    },
  };
  if (id !== undefined) {
    out.cve = {
      id,
      forward: withRow(items.find((i) => i.id === id)) ?? uncounted.find((i) => i.id === id) ?? null,
      backtest: withRow(b?.items.find((i) => i.id === id)),
    };
  }
  return out;
}

// ── search_cves ─────────────────────────────────────────────────────────────────────────────

export interface SearchArgs {
  query: string;
  tiers?: Tier[];
  knob?: number;
  limit?: number;
  offset?: number;
}

export async function searchCves(call: DataCall, a: SearchArgs, now: number): Promise<McpSearchResult> {
  const knob = a.knob ?? KNOB_DEFAULT;
  const terms = a.query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) throw new InputError('query needs at least one word.');
  if (terms.length > LIMITS.queryWords) throw new InputError(MCP_MSG.tooManyWords(LIMITS.queryWords));
  const tiers = a.tiers?.length ? new Set(a.tiers) : null;
  const { rows, hay } = await call.file('index.json', parse.rows);
  const meta = await call.meta();
  const hits: Row[] = [];
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (terms.every((t) => hay[i].includes(t)) && (!tiers || tiers.has(tierFor(r.s, r.x === 1, r.w === 1, knob)))) hits.push(r);
  }
  hits.sort(byScore);
  const p = page(hits, a.offset, a.limit ?? 20);
  return {
    data: await dataBlock(call, now),
    query: a.query,
    knob,
    scope: `CVEs published in the ${meta.window.days}-day window (index.json), matched on ID, CNA, vendor, product and title. For older CVEs, use get_verdict.`,
    ...p,
    items: p.items.map((r) => mcpRow(r, knob)),
  };
}

// ── check_inventory ─────────────────────────────────────────────────────────────────────────

export interface InventoryArgs {
  names: string[];
  tiers?: Tier[];
  knob?: number;
  per_name?: number;
}

/** Bytes of JSON all names may take together: 200 names of 80 ASCII characters fit. */
export const NAMES_BUDGET = 20 * 1024;

/** Control, format and lone surrogate characters: no vendor name has them, and JSON escapes each in 6 bytes. */
const ODD_CHAR_RE = /[\p{Cc}\p{Cf}\p{Cs}]/u;

/** Names as the watchlist keeps them (shared/watch.ts): normalized, deduped, 1 to WATCH_NAME_MAX characters. */
export function watchNames(raw: readonly string[]): string[] {
  const out: string[] = [];
  for (const s of raw) {
    const n = normalizeName(s);
    if (!n || n.length > LIMITS.nameChars) throw new InputError(MCP_MSG.badName(LIMITS.nameChars));
    if (ODD_CHAR_RE.test(n)) throw new InputError(MCP_MSG.oddName);
    if (!out.includes(n)) out.push(n);
  }
  if (out.length > LIMITS.names) throw new InputError(`names takes at most ${LIMITS.names} names.`);
  if (Buffer.byteLength(JSON.stringify(out)) > NAMES_BUDGET) throw new InputError(MCP_MSG.namesTooLong);
  return out;
}

const TIER_RANK: Readonly<Record<Tier, number>> = { exploited: 0, likely: 1, watch: 2, quiet: 3 };

/** Soonest KEV due date first, none last. */
const byDue = (a: string | null, b: string | null) => (a === b ? 0 : a === null ? 1 : b === null ? -1 : a.localeCompare(b));

/** Most urgent first: tier, then the soonest KEV due date, then score, newest, id. */
const byUrgency = (a: McpInventoryItem, b: McpInventoryItem) =>
  TIER_RANK[a.tier] - TIER_RANK[b.tier] || byDue(a.kev_due, b.kev_due) || b.score - a.score || b.published.localeCompare(a.published) || a.id.localeCompare(b.id);

export async function checkInventory(call: DataCall, a: InventoryArgs, now: number): Promise<McpInventoryResult> {
  const knob = a.knob ?? KNOB_DEFAULT;
  const names = watchNames(a.names);
  const tiers: Tier[] = a.tiers?.length ? [...new Set(a.tiers)] : [...TIERS];
  const want = new Set(tiers);
  const { rows } = await call.file('index.json', parse.rows);
  const woke = await call.file('woke.json', parse.woke);
  // Window CVEs, then old CVEs that woke up (not in the window, so never twice).
  const seen = new Set(rows.map((r) => r.id));
  const tracked = [...rows, ...woke.items.map((i) => i.row).filter((r) => !seen.has(r.id))];
  const matched = new Map<string, Row[]>(names.map((n) => [n, []]));
  for (const r of tracked) {
    if (!matchesName(names, r.v, r.p)) continue;
    for (const n of names) if (matchesName([n], r.v, r.p)) matched.get(n)!.push(r);
  }
  const all = names.map((name) => {
    const rs = matched.get(name)!;
    const items = rs
      .map((r): McpInventoryItem => {
        const m = mcpRow(r, knob);
        return { id: m.id, tier: m.tier, verdict: VERDICT[m.tier], score: m.score, kev_due: m.kev_due, in_kev: m.in_kev, exploited: m.exploited, weaponized: m.weaponized, published: m.published, vendor: m.vendor, product: m.product, title: m.title };
      })
      .filter((i) => want.has(i.tier))
      .sort(byUrgency);
    const slug = slugify(name);
    return { name, feed: slug ? `${BRAND.siteUrl}/feeds/v/${slug}.xml` : null, matched: rs.length, items };
  });
  const meta = await call.meta();
  const data = await dataBlock(call, now);
  const scope = `CVEs published in the ${meta.window.days}-day window (index.json) and old CVEs that woke up (woke.json). A name matches a CVE whose vendor or product equals it, ignoring case and extra spaces. Older CISA KEV CVEs are not listed here: use kev_due or get_verdict.`;
  const asked = a.per_name ?? 10;
  // Every name's first `asked` CVEs, most urgent first across all names: when the answer must be
  // cut, the least urgent go first, so an exploited CVE is never left out for a quiet one.
  const queue = all
    .flatMap(({ items }, n) => items.slice(0, asked).map((item, k) => ({ item, k, n })))
    .sort((x, y) => byUrgency(x.item, y.item) || x.k - y.k || x.n - y.n);
  const build = (shown: number): McpInventoryResult => {
    const count = new Array<number>(all.length).fill(0);
    for (const { n } of queue.slice(0, shown)) count[n]++;
    return {
      data,
      knob,
      tiers,
      per_name: asked,
      note: shown < queue.length ? MCP_MSG.inventoryCut(shown, queue.length) : null,
      scope,
      names: all.map(({ name, feed, matched, items }, n): McpInventoryName => {
        const kept = items.slice(0, count[n]);
        return { name, feed, matched, total: items.length, omitted: items.length - kept.length, no_match: matched === 0, items: kept };
      }),
    };
  };
  // Never cut silently: the note says how many were shown, and each name's omitted counts the rest.
  // The most CVEs that fit, by bisection: the size grows with every CVE shown.
  const fits = (r: McpInventoryResult) => Buffer.byteLength(JSON.stringify(r)) <= INVENTORY_BUDGET;
  let out = build(queue.length);
  if (!fits(out)) {
    let lo = 0;
    let hi = queue.length - 1;
    out = build(0);
    if (!fits(out)) throw new InputError(MCP_MSG.namesTooLong);
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      const r = build(mid);
      if (fits(r)) [lo, out] = [mid, r];
      else hi = mid - 1;
    }
  }
  return out;
}

// ── changes_since ───────────────────────────────────────────────────────────────────────────

export interface ChangesArgs {
  since: string;
  until?: string;
  names?: string[];
  types?: EventType[];
  limit?: number;
  offset?: number;
}

/** An event as the agent gets it: only EventItem's fields, upstream text on one line and capped. */
function eventOut(e: EventItem): EventItem {
  return {
    id: e.id,
    at: e.at,
    type: e.type,
    cve: e.cve,
    vendor: cut(oneLine(e.vendor), TITLE_MAX),
    product: cut(oneLine(e.product), TITLE_MAX),
    tier_before: e.tier_before,
    tier_after: e.tier_after,
    score: e.score,
    title: cut(oneLine(e.title), TITLE_MAX),
    via: e.via,
    url: e.url,
    detail: cut(oneLine(e.detail), DETAIL_MAX),
    backfill: e.backfill,
  };
}

export async function changesSince(call: DataCall, a: ChangesArgs, now: number): Promise<McpChangesResult> {
  const sinceMs = dateArg('since', a.since);
  // A date-time is exclusive, so next_since repeats nothing; a date takes the whole day, from 00:00:00Z.
  const after = a.since.length === 10 ? (ms: number) => ms >= sinceMs : (ms: number) => ms > sinceMs;
  const untilMs = a.until === undefined ? null : dateArg('until', a.until);
  const names = a.names?.length ? watchNames(a.names) : null;
  const types = a.types?.length ? [...new Set(a.types)] : null;
  const ev = await call.file('events.json', parse.events);
  const genMs = Date.parse(ev.generated_at);
  const to = new Date(genMs).toISOString();
  const from = new Date(genMs - ev.days * DAY_MS).toISOString();
  if (sinceMs < Date.parse(from)) throw new InputError(MCP_MSG.beforeLog(from, to, ev.days));
  const want = types && new Set(types);
  const all = ev.items
    .filter((e) => {
      const at = Date.parse(e.at);
      return after(at) && (untilMs === null || at <= untilMs) && (!want || want.has(e.type)) && (!names || matchesName(names, e.vendor, e.product));
    })
    // Newest first, as the file is; a stable sort keeps the file's order within one run.
    .sort((x, y) => Date.parse(y.at) - Date.parse(x.at));
  const p = page(all, a.offset, a.limit ?? 25);
  return {
    data: await dataBlock(call, now),
    since: new Date(sinceMs).toISOString(),
    until: untilMs === null ? null : new Date(untilMs).toISOString(),
    log: { from, to, days: ev.days, previous_at: ev.previous_at ?? null, max_items: ev.max_items, capped: ev.items.length >= ev.max_items },
    // With until, every page names the same next_since, even when the log is republished between pages.
    next_since: new Date(untilMs === null ? genMs : Math.min(untilMs, genMs)).toISOString(),
    names,
    types,
    ...p,
    items: p.items.map(eventOut),
  };
}

// ── check_dependencies ──────────────────────────────────────────────────────────────────────

export interface DependenciesArgs {
  paths?: string[];
  knob?: number;
  include_quiet?: boolean;
}

/** Bytes of JSON check_dependencies answers with at most (about 17,000 tokens); the least urgent findings are left out to fit. */
export const DEPENDENCIES_BUDGET = 60 * 1024;
export const DEPENDENCY_LIMITS = { paths: 20, pathChars: 1024 } as const;
/** check_dependencies reads up to two larger files (packages-older.json is about 2 MB gzip): a longer deadline than other tools. */
export const DEPENDENCIES_TIMEOUT_MS = 30_000;

/**
 * Paths inside `root` to hand to discover(): each must resolve, through any symbolic link, to a place
 * inside root, and a file must have a lockfile or SBOM name. That keeps an agent that was talked into
 * it from reading other files: nothing else is opened, and file errors never quote file content.
 */
export function dependencyPaths(raw: readonly string[], root: string): string[] {
  const realRoot = realpathSync(root);
  const inside = (p: string) => {
    const r = relative(realRoot, p);
    return r === '' || (!r.startsWith('..') && !isAbsolute(r));
  };
  return raw.map((p) => {
    const abs = resolve(root, p);
    let real: string;
    try {
      real = realpathSync(abs);
    } catch {
      return p; // missing: discover() reports it
    }
    if (!inside(real)) throw new InputError(MCP_MSG.outsideRoot(p));
    if (statSync(real).isFile() && !isCheckable(basename(real))) throw new InputError(MCP_MSG.notCheckable(p));
    return relative(root, abs) || '.';
  });
}

/** A file error as the agent sees it: the parser's fixed messages, and never a quote from the file. */
function fileError(e: string | null): string | null {
  if (e === null) return null;
  if (e.startsWith('This looks like JSON')) return 'This looks like JSON, but it could not be read.';
  return e.startsWith('could not be read') ? 'could not be read' : e;
}

const groupRank: Readonly<Record<Group, number>> = { exploited: 0, likely: 1, watch: 2, quiet: 3, possible: 4 };

export async function checkDependencies(call: DataCall, a: DependenciesArgs, now: number, root = process.cwd()): Promise<McpDependenciesResult> {
  const knob = a.knob ?? KNOB_DEFAULT;
  const paths = dependencyPaths(a.paths?.length ? a.paths : ['.'], root);
  const found = discover(paths, root);
  if (!found.files.length) throw new InputError(MCP_MSG.noDependencyFiles((a.paths?.length ? a.paths : ['.']).join(', ')));
  const tracked = await call.file('packages.json', parse.packages);
  let older: PackagesFile | null = null;
  let olderMissing: string | null = null;
  try {
    older = await call.file('packages-older.json', parse.packages);
  } catch (e) {
    if (!(e instanceof DataError)) throw e;
    olderMissing = e instanceof DataUnavailable ? 'packages-older.json is not published in this data' : e.message;
  }
  const trackedIds = new Set(rowsFromTable(tracked.cves).map((r) => r.id));
  const olderIds = new Set(older ? rowsFromTable(older.cves).map((r) => r.id).filter((id) => !trackedIds.has(id)) : []);
  const report = checkFiles(found.files, root, mergePackageFiles(tracked, older), knob, { olderIds, olderError: olderMissing });
  const counts = countByGroup(report.findings);
  const shown = report.findings.filter((f) => a.include_quiet || f.group !== 'quiet').sort((x, y) => groupRank[x.group] - groupRank[y.group]);
  const items = shown.map((f): McpDependencyFinding => ({
    cve: f.row.id,
    group: f.group,
    verdict: f.group === 'possible' ? 'Possibly affected: the version in the file could not be compared with the advisory.' : VERDICT[f.group],
    score: f.row.s,
    in_kev: f.row.k === 1,
    kev_due: f.row.kd,
    exploited: f.row.x === 1,
    weaponized: f.row.w === 1,
    ecosystem: f.pkg.eco,
    package: cut(oneLine(f.pkg.name), TITLE_MAX),
    named: f.pkg.named ? cut(oneLine(f.pkg.named), TITLE_MAX) : null,
    version: f.pkg.version === null ? null : cut(oneLine(f.pkg.version), 64),
    fixed_in: f.fixedIn,
    advisories: f.pkg.advisories.map((x) => x.id),
    file: f.file,
    line: f.line,
    tracked: f.tracked,
    url: findingUrl(f),
    title: cut(oneLine(f.row.t), TITLE_MAX),
  }));
  const data = await dataBlock(call, now);
  const scope = `${olderMissing === null ? `Every CVE that one of ${report.coverage.advisories.toLocaleString('en-US')} OSV.dev advisories ties to a package version, in npm, PyPI, Maven, Go, crates.io, RubyGems, Packagist and NuGet` : 'Tracked CVEs only'}. Not checked: advisories without a CVE ID (malware reports among them), other ecosystems (deb, rpm, apk, containers), and bugs no advisory names yet. Tracked CVEs (tracked: true) have a page and get_verdict knows them; older ones link to cve.org.`;
  const build = (n: number): McpDependenciesResult => ({
    data,
    knob,
    scope,
    note: [n < items.length ? MCP_MSG.dependenciesCut(n, items.length) : null, olderMissing === null ? null : MCP_MSG.olderMissing(olderMissing)].filter(Boolean).join(' ') || null,
    files: report.files.map((f) => ({ path: f.path, format: f.format, packages: f.result?.distinct ?? 0, error: fileError(f.error) })),
    counts,
    packages_checked: report.checked,
    coverage: { tracked_cves: report.coverage.tracked, older_cves: report.coverage.older, advisories: report.coverage.advisories, older_missing: olderMissing },
    total: items.length,
    omitted: items.length - n,
    items: items.slice(0, n),
  });
  // The most findings that fit, by bisection (most urgent first, so an exploited CVE is never cut for a quiet one).
  const fits = (r: McpDependenciesResult) => Buffer.byteLength(JSON.stringify(r)) <= DEPENDENCIES_BUDGET;
  let out = build(items.length);
  if (!fits(out)) {
    let lo = 0;
    let hi = items.length - 1;
    out = build(0);
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      const r = build(mid);
      if (fits(r)) [lo, out] = [mid, r];
      else hi = mid - 1;
    }
  }
  return out;
}
