/**
 * "What changed": escalations since the previous run, merged with the previous changes.json.
 *
 * An item is recorded when a CVE's tier rose, or a new E (exploitation) or X (exploit) chip
 * appeared. Rows missing from the previous index count as new arrivals only when they reach
 * exploited/likely and are genuinely new: published after the previous index's oldest row, or
 * (outside the window) KEV-listed but absent from the previous kev.json.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CHIP_BY_ID } from '../../shared/model';
import { SCHEMA_VERSION, TIERS, rowFromColumns, type Change, type ChangesFile, type Row, type Tier } from '../../shared/contract';
import { DAY_MS } from './util/dates';
import { asObject } from './util/json';

/** Items older than this are dropped. Callers use it to pick recent KEV additions outside the window. */
export const CHANGES_RETENTION_DAYS = 7;
const MAX_ITEMS = 500;

const rank = (t: Tier) => TIERS.indexOf(t);
const isTier = (t: unknown): t is Tier => typeof t === 'string' && (TIERS as readonly string[]).includes(t);
const passed = (t: Tier) => t === 'exploited' || t === 'likely';

/** E/X chips that raise priority. */
function isEscalationChip(id: string): boolean {
  const def = CHIP_BY_ID[id];
  return !!def && (def.family === 'E' || def.family === 'X') && def.polarity === 'up';
}

function chipSet(r: Row): string[] {
  return [...new Set([...(r.k ? ['kev.listed'] : []), ...r.c])];
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

/** Previous index rows by id, or null when there is no usable previous index. */
function previousRows(root: string): Map<string, Row> | null {
  const t = asObject(readJson(join(root, 'v1', 'index.json')));
  if (!t || t.schema_version !== SCHEMA_VERSION || !Array.isArray(t.cols) || !Array.isArray(t.rows)) return null;
  const cols = t.cols.map(String);
  const valid = t.rows
    .filter(Array.isArray)
    .map((values) => rowFromColumns(cols, values))
    .filter((r) => typeof r.id === 'string' && isTier(r.tier) && Array.isArray(r.c) && Number.isFinite(Date.parse(r.pub)));
  return new Map(valid.map((r) => [r.id, r]));
}

/** CVE ids in the previous kev.json, or null when there is no usable one. */
function previousKevIds(root: string): Set<string> | null {
  const f = asObject(readJson(join(root, 'v1', 'kev.json')));
  if (!f || f.schema_version !== SCHEMA_VERSION || !Array.isArray(f.entries)) return null;
  return new Set(f.entries.map((e) => asObject(e)?.id).filter((id): id is string => typeof id === 'string'));
}

function previousItems(root: string): Change[] {
  const f = asObject(readJson(join(root, 'v1', 'changes.json')));
  if (!f || f.schema_version !== SCHEMA_VERSION || !Array.isArray(f.items)) return [];
  return f.items.filter((item): item is Change => {
    const i = asObject(item);
    return (
      !!i &&
      typeof i.id === 'string' &&
      typeof i.at === 'string' &&
      Number.isFinite(Date.parse(i.at)) &&
      isTier(i.to) &&
      (i.from === null || isTier(i.from)) &&
      Array.isArray(i.added) &&
      i.added.every((a) => typeof a === 'string')
    );
  });
}

function diff(prev: Row | undefined, cur: Row, at: string): Change | null {
  const prevChips = new Set(prev ? chipSet(prev) : []);
  const added = chipSet(cur).filter((id) => !prevChips.has(id));
  if (!prev) return passed(cur.tier) ? { id: cur.id, at, from: null, to: cur.tier, added } : null;
  if (rank(cur.tier) < rank(prev.tier) || added.some(isEscalationChip)) {
    return { id: cur.id, at, from: prev.tier, to: cur.tier, added };
  }
  return null;
}

/**
 * @param current rows to compare: the window index plus KEV-listed rows outside the window
 *   that were added to KEV within the last CHANGES_RETENTION_DAYS.
 * @param previousRoot previous output root (v1/index.json, v1/kev.json, v1/changes.json), if any.
 */
export function buildChanges(current: Row[], previousRoot: string | null, now: Date): ChangesFile {
  const at = now.toISOString();
  const prevRows = previousRoot ? previousRows(previousRoot) : null;
  const merged = new Map<string, Change>();
  // Previous items are newest first; keep one per CVE.
  for (const item of previousRoot ? previousItems(previousRoot) : []) if (!merged.has(item.id)) merged.set(item.id, item);

  if (prevRows && previousRoot) {
    const prevKev = previousKevIds(previousRoot);
    let oldestPrev = Infinity;
    for (const r of prevRows.values()) oldestPrev = Math.min(oldestPrev, Date.parse(r.pub));
    /** A row the previous index could not contain: new only if it is a fresh KEV listing. */
    const knownBefore = (r: Row) => Date.parse(r.pub) <= oldestPrev && !(r.k && prevKev && !prevKev.has(r.id));

    for (const cur of current) {
      const prev = prevRows.get(cur.id);
      if (!prev && knownBefore(cur)) continue;
      const fresh = diff(prev, cur, at);
      if (!fresh) continue;
      const old = merged.get(cur.id);
      if (!old) {
        merged.set(cur.id, fresh);
        continue;
      }
      const newChips = fresh.added.filter((id) => !old.added.includes(id));
      if (rank(fresh.to) >= rank(old.to) && newChips.length === 0) continue; // already reported
      merged.set(cur.id, { id: cur.id, at, from: old.from, to: fresh.to, added: [...newChips, ...old.added] });
    }
  }

  const cutoff = now.getTime() - CHANGES_RETENTION_DAYS * DAY_MS;
  const items = [...merged.values()]
    .filter((i) => Date.parse(i.at) >= cutoff && Date.parse(i.at) <= now.getTime())
    .sort((a, b) => b.at.localeCompare(a.at) || rank(a.to) - rank(b.to) || a.id.localeCompare(b.id))
    .slice(0, MAX_ITEMS);
  return { schema_version: SCHEMA_VERSION, generated_at: at, items };
}
