/**
 * Patch-day batches: (CNA, UTC publish date) groups of at least BATCH_MIN window records.
 * Members get the `batch` info chip and `ScoredCve.batch`; the Batch summary is returned.
 */
import { cnaName, isBulkCna } from '../../shared/cna';
import type { Batch, Tier } from '../../shared/contract';
import { BATCH_MIN, chip } from '../../shared/model';
import { toRow } from './rows';
import { formatInt, monthDay, orderReasons, utcDay } from './score';
import type { ScoredCve } from './types';

const MAX_FAMILIES = 8;
const MAX_TOP = 5;

/** "Microsoft Corporation" → "microsoft-corporation". */
export function slugify(s: string): string {
  return (
    s
      .normalize('NFKD')
      .replace(/\p{M}+/gu, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'unknown'
  );
}

const passed = (t: Tier) => t === 'exploited' || t === 'likely';

/** Highest score first, then newest, then id (stable output). */
export function byScoreThenNewest(a: ScoredCve, b: ScoredCve): number {
  return b.score - a.score || b.cve.published.localeCompare(a.cve.published) || a.cve.id.localeCompare(b.cve.id);
}

/**
 * Group window records into batches, tag their members, and return the batches newest first.
 * Mutates `reasons` and `batch` of the members (call before building rows/details).
 */
export function assignBatches(scored: ScoredCve[]): Batch[] {
  const groups = new Map<string, ScoredCve[]>();
  for (const s of scored) {
    if (!s.cve.inWindow) continue;
    const key = `${s.cve.cna}\u0000${utcDay(s.cve.published)}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = []));
    g.push(s);
  }

  const def = chip('batch');
  const batches: Batch[] = [];
  for (const members of groups.values()) {
    if (members.length < BATCH_MIN) continue;
    const { cna, published } = members[0].cve;
    const date = utcDay(published);
    const id = `${slugify(cna)}-${date}`;
    const kind = isBulkCna(cna) ? 'bulk release' : 'patch day';
    const label = `Part of ${cnaName(cna)} ${kind} · ${monthDay(date)} (${formatInt(members.length)})`;

    const byTier: Record<Tier, number> = { exploited: 0, likely: 0, watch: 0, quiet: 0 };
    const families = new Map<string, { count: number; passed: number }>();
    for (const s of members) {
      s.batch = id;
      s.reasons = orderReasons([
        ...s.reasons.filter((r) => r.id !== def.id),
        { id: def.id, label, polarity: def.polarity, family: def.family, points: def.points, source: def.source, at: date },
      ]);
      byTier[s.tier]++;
      const product = s.cve.affected[0]?.product.trim();
      if (!product) continue;
      const fam = families.get(product) ?? { count: 0, passed: 0 };
      fam.count++;
      if (passed(s.tier)) fam.passed++;
      families.set(product, fam);
    }

    batches.push({
      id,
      cna,
      date,
      count: members.length,
      by_tier: byTier,
      families: [...families.entries()]
        .map(([name, v]) => ({ name, ...v }))
        .sort((a, b) => b.count - a.count || b.passed - a.passed || a.name.localeCompare(b.name))
        .slice(0, MAX_FAMILIES),
      top: [...members].sort(byScoreThenNewest).slice(0, MAX_TOP).map(toRow),
    });
  }

  return batches.sort((a, b) => b.date.localeCompare(a.date) || b.count - a.count || a.id.localeCompare(b.id));
}
