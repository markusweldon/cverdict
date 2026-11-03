/**
 * The six MCP tools as plain functions over the published files: (call, args, now) -> result.
 * No SDK imports, so they are unit-tested with a fake fetch. Every result starts with `data`, which
 * names the run and every file the answer came from (McpData in shared/contract.ts).
 */
import {
  KNOB_DEFAULT,
  SIGNAL_MIN_SCORE,
  tierFor,
  type BacktestItem,
  type CveDetail,
  type McpData,
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
  type ReceiptItem,
  type Row,
  type Tier,
  type WakeKind,
} from '../../shared/contract';
import { BRAND } from '../../shared/brand';
import { MCP_MSG, VERDICT } from '../../shared/mcp';
import { BASE_POINTS } from '../../shared/model';
import { CVE_ID_RE, shardOf } from '../../shared/shard';
import { parse, type DataCall } from './data';

/** A request the tool cannot answer as asked (isError: true). A filter is never silently dropped. */
export class InputError extends Error {}

export const LIMITS = { ids: 15, detailIds: 5, page: 50, offset: 100_000, queryWords: 8, withinDays: 60, overdueDays: 14 } as const;

const DAY_MS = 86_400_000;
const TITLE_MAX = 160;

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
    sources_down: m.sources.filter((s) => !s.ok).map((s) => s.id),
    sources_stale: m.sources.filter((s) => s.ok && s.stale).map((s) => s.id),
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
}

export async function kevDue(call: DataCall, a: KevDueArgs, now: number): Promise<McpKevDueResult> {
  const kev = await call.file('kev.json', parse.kev);
  const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
  const today = day(now);
  const from = day(Date.parse(today) - (a.overdue_days ?? 7) * DAY_MS);
  const to = day(Date.parse(today) + (a.within_days ?? 7) * DAY_MS);
  const items = kev.entries
    .filter((e) => e.due_date >= from && e.due_date <= to)
    .sort((x, y) => x.due_date.localeCompare(y.due_date) || x.id.localeCompare(y.id))
    .map((e) => ({
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
  return { data: await dataBlock(call, now), today_utc: today, from, to, catalog_version: kev.catalog_version, total: items.length, items };
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
