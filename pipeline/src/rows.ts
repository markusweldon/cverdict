/**
 * ScoredCve → public shapes: the compact list Row and the full CveDetail stored in shards.
 */
import type { CveDetail, Reason, Row } from '../../shared/contract';
import { CHIP_BY_ID, SCORE_MODEL } from '../../shared/model';
import type { ScoredCve } from './types';
import { truncate } from './util/text';

const ROW_CHIPS = 4;
const ROW_TITLE_MAX = 160;

/**
 * Strongest chips for list rows: positive chips by weight (desc), then information chips
 * (catalogue order, as they appear in reasons[]), then negative chips (most negative first).
 * Chips that lost within their family (0 points) and unknowns are left out. Positive chips are
 * ranked by catalogue points first because the winning E chip's actual points absorb the
 * exploited floor and can be smaller than an X chip's, yet it is the strongest evidence.
 */
export function topChipIds(reasons: readonly Reason[], max = ROW_CHIPS): string[] {
  const weight = (r: Reason) => CHIP_BY_ID[r.id]?.points ?? r.points;
  const positive = reasons.filter((r) => r.points > 0).sort((a, b) => weight(b) - weight(a) || b.points - a.points);
  const info = reasons.filter((r) => r.polarity === 'info');
  const negative = reasons.filter((r) => r.points < 0).sort((a, b) => a.points - b.points);
  return [...new Set([...positive, ...info, ...negative].map((r) => r.id))].slice(0, max);
}

/** Every chip id that fired, family losers included, unknowns left out (Row.r, for filtering). */
export function firedChipIds(reasons: readonly Reason[]): string[] {
  return [...new Set(reasons.filter((r) => r.polarity !== 'unknown').map((r) => r.id))];
}

const bit = (b: boolean): 0 | 1 => (b ? 1 : 0);

/** ISO 8601 UTC without fractional seconds: rows don't need them and they cost ~7% of index.json gzip. */
const toSeconds = (iso: string) => iso.replace(/\.\d+Z$/, 'Z');

function isKevListed(s: ScoredCve): boolean {
  return s.reasons.some((r) => r.id === 'kev.listed');
}

export function toRow(s: ScoredCve): Row {
  const { cve } = s;
  const first = cve.affected[0];
  return {
    id: cve.id,
    pub: toSeconds(cve.published),
    cna: cve.cna,
    v: first?.vendor ?? '',
    p: first?.product ?? '',
    t: truncate(cve.title?.trim() || cve.description, ROW_TITLE_MAX),
    s: s.score,
    tier: s.tier,
    x: bit(s.exploited),
    w: bit(s.weaponized),
    k: bit(isKevListed(s)),
    ai: bit(cve.aiCredit !== null),
    c: topChipIds(s.reasons),
    r: firedChipIds(s.reasons),
    cv: cve.cvss?.score ?? null,
    e: s.epss?.score ?? null,
    kd: s.kev?.due_date ?? null,
    b: s.batch,
  };
}

export function toDetail(s: ScoredCve): CveDetail {
  const { cve } = s;
  return {
    id: cve.id,
    state: 'PUBLISHED',
    published: cve.published,
    reserved: cve.reserved,
    updated: cve.updated,
    cna: cve.cna,
    title: cve.title,
    description: cve.description,
    cvss: cve.cvss,
    cwe: cve.cwe,
    affected: cve.affected,
    ssvc: cve.ssvc,
    kev: s.kev,
    epss: s.epss,
    exploits: s.exploits,
    ai_credit: cve.aiCredit,
    tags: cve.tags,
    batch: s.batch,
    score: { value: s.score, tier: s.tier, raw: s.raw, model: SCORE_MODEL },
    reasons: s.reasons,
    unknowns: s.unknowns,
    timeline: s.timeline,
    references: cve.references,
  };
}
