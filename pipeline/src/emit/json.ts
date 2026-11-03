/**
 * Public JSON files (docs/SPEC.md §2 "Emit"): builders for each file shape and the writer.
 * Every file is minified UTF-8 JSON carrying `schema_version` and `generated_at`.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import {
  ROW_COLS,
  SCHEMA_VERSION,
  type BatchesFile,
  type ChangesFile,
  type CveDetail,
  type CveShard,
  type KevEntry,
  type KevFile,
  type Meta,
  type Row,
  type RowTable,
  type StatsFile,
  type WokeFile,
} from '../../../shared/contract';
import { SHARD_COUNT, shardOf } from '../../../shared/shard';
import type { KevCatalog, ScoredCve } from '../types';
import { addDays, ymd } from '../util/dates';

/** Output layout, relative to the output root. */
export const PATHS = {
  meta: 'v1/meta.json',
  signal: 'v1/signal.json',
  index: 'v1/index.json',
  batches: 'v1/batches.json',
  kev: 'v1/kev.json',
  stats: 'v1/stats.json',
  changes: 'v1/changes.json',
  woke: 'v1/woke.json',
  state: 'v1/state.json',
  receipts: 'v1/receipts.json',
  shard: (name: string) => `v1/cve/${name}.json`,
  signalFeed: 'feeds/signal.xml',
  kevFeed: 'feeds/kev.xml',
  kevDueIcs: 'feeds/kev-due.ics',
  wokeFeed: 'feeds/woke.xml',
} as const;

/** kev.json keeps entries added in the last KEV_RECENT_DAYS, or due from KEV_DUE_LOOKBACK_DAYS ago onward. */
export const KEV_RECENT_DAYS = 30;
const KEV_DUE_LOOKBACK_DAYS = 14;

/** All shard names, "00" … "ff". */
export const SHARD_NAMES: readonly string[] = Array.from({ length: SHARD_COUNT }, (_, i) => i.toString(16).padStart(2, '0'));

export function rowTable(rows: readonly Row[], scope: string, generatedAt: string): RowTable {
  return {
    schema_version: SCHEMA_VERSION,
    generated_at: generatedAt,
    scope,
    cols: ROW_COLS,
    rows: rows.map((r) => ROW_COLS.map((c) => r[c])),
  };
}

/** Every shard is written (empty ones too), so a client lookup never 404s on a valid shard. */
export function buildShards(details: readonly CveDetail[], generatedAt: string): Map<string, CveShard> {
  const shards = new Map(SHARD_NAMES.map((name) => [name, { schema_version: SCHEMA_VERSION, generated_at: generatedAt, items: {} } as CveShard]));
  for (const d of details) shards.get(shardOf(d.id))!.items[d.id] = d;
  return shards;
}

/** The UTC day `days` before `now` (negative: after), as YYYY-MM-DD. */
export function daysAgo(now: Date, days: number): string {
  return ymd(addDays(now, -days));
}

export function buildKevFile(kev: KevCatalog, scoredById: ReadonlyMap<string, ScoredCve>, now: Date): KevFile {
  const addedSince = daysAgo(now, KEV_RECENT_DAYS);
  const dueSince = daysAgo(now, KEV_DUE_LOOKBACK_DAYS);
  const entries: KevEntry[] = [];
  for (const k of kev.entries.values()) {
    if (k.dateAdded < addedSince && k.dueDate < dueSince) continue;
    const s = scoredById.get(k.cveID);
    const triage = k.forensicTriage?.trim().toLowerCase();
    entries.push({
      id: k.cveID,
      vendor: k.vendorProject,
      product: k.product,
      name: k.vulnerabilityName,
      date_added: k.dateAdded,
      due_date: k.dueDate,
      ransomware: k.knownRansomwareCampaignUse,
      forensic_triage: triage === 'yes' ? true : triage === 'no' ? false : null,
      description: k.shortDescription,
      required_action: k.requiredAction,
      in_window: s?.cve.inWindow ?? false,
      score: s?.score ?? null,
    });
  }
  entries.sort((a, b) => b.date_added.localeCompare(a.date_added) || a.due_date.localeCompare(b.due_date) || a.id.localeCompare(b.id));
  return { schema_version: SCHEMA_VERSION, generated_at: now.toISOString(), catalog_version: kev.version, entries };
}

export interface DataFiles {
  meta: Meta;
  signal: RowTable;
  index: RowTable;
  shards: ReadonlyMap<string, CveShard>;
  batches: BatchesFile;
  kev: KevFile;
  stats: StatsFile;
  changes: ChangesFile;
  woke: WokeFile;
}

/** Serialise the JSON tree: relative path → minified JSON. */
export function serializeData(d: DataFiles): Map<string, string> {
  const files = new Map<string, string>([
    [PATHS.meta, JSON.stringify(d.meta)],
    [PATHS.signal, JSON.stringify(d.signal)],
    [PATHS.index, JSON.stringify(d.index)],
    [PATHS.batches, JSON.stringify(d.batches)],
    [PATHS.kev, JSON.stringify(d.kev)],
    [PATHS.stats, JSON.stringify(d.stats)],
    [PATHS.changes, JSON.stringify(d.changes)],
    [PATHS.woke, JSON.stringify(d.woke)],
  ]);
  for (const [name, shard] of d.shards) files.set(PATHS.shard(name), JSON.stringify(shard));
  return files;
}

/** Write relative path → content under `root`, creating directories as needed. */
export async function writeFiles(root: string, files: ReadonlyMap<string, string>): Promise<void> {
  const dirs = new Set([...files.keys()].map((p) => dirname(join(root, p))));
  await Promise.all([...dirs].map((d) => mkdir(d, { recursive: true })));
  await Promise.all([...files].map(([p, content]) => writeFile(join(root, p), content, 'utf8')));
}
