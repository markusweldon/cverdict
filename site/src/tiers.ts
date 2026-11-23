/** Presentation metadata for tiers, chip families and sources, plus the plain-language verdict. */
import { WATCH_FLOOR, tierFor, type CveDetail, type Family, type Reason, type SourceId, type Tier } from '../../shared/contract';
import { CHIP_BY_ID, type ChipDef } from '../../shared/model';
import { verdict as sharedVerdict } from '../../shared/verdict';

export const TIER_META: Readonly<Record<Tier, { label: string; verdict: string; blurb: string }>> = {
  exploited: { label: 'Exploited', verdict: 'Patch now', blurb: 'Confirmed exploitation: CISA KEV, ENISA EU KEV, CIRCL, CISA SSVC “active”, or the vendor says so.' },
  likely: { label: 'Likely', verdict: 'Likely next', blurb: 'A public exploit artifact, or a score that clears the evidence bar.' },
  watch: { label: 'Watch', verdict: 'Watch', blurb: `Some evidence, below the evidence bar but above the watch floor (${WATCH_FLOOR}).` },
  quiet: { label: 'Quiet', verdict: 'Quiet', blurb: 'No evidence yet. Quiet ≠ safe.' },
};

export const FAMILY_META: Readonly<Record<Family, { label: string; blurb: string }>> = {
  E: { label: 'Exploitation', blurb: 'Confirmed exploitation. Any one puts the CVE in the Exploited tier.' },
  X: { label: 'Exploit artifacts', blurb: 'Public exploits and exploit prediction. Only the strongest counts.' },
  SEV: { label: 'Severity', blurb: 'CVSS base score from the CNA, or CISA-ADP when the CNA gave none.' },
  SSVC: { label: 'CISA SSVC', blurb: 'Two independent decision points from CISA Vulnrichment; they add.' },
  PRIOR: { label: 'History', blurb: 'Whether this vendor or product has been exploited before.' },
  NOISE: { label: 'Noise filters', blurb: 'Only applied when there is no exploitation and no exploit artifact.' },
  INFO: { label: 'Context', blurb: 'Information only: 0 points.' },
};

export const FAMILY_ORDER: readonly Family[] = ['E', 'X', 'SEV', 'SSVC', 'PRIOR', 'NOISE', 'INFO'];

/**
 * Display groups: the sections the CVE page, the Method chip glossary and the Explore reason
 * filter show. They follow the scoring families, plus Exposure, which holds chips that describe
 * the target rather than an exploit. Display only: fast.lane still scores in X (the strongest X
 * chip counts) and edge.device stays an INFO chip worth 0.
 */
export type Group = Family | 'EXPOSURE';
export const GROUP_META: Readonly<Record<Group, { label: string; blurb: string }>> = {
  ...FAMILY_META,
  X: { label: 'Exploit artifacts', blurb: 'Public exploits and exploit prediction. Only the strongest counts, including the fast lane under Exposure.' },
  EXPOSURE: { label: 'Exposure', blurb: 'Exposed, automatable and high impact: attacked fast, often before any exploit is public. Scored with exploit artifacts: the strongest counts.' },
};
/** Exposure right after Exploit artifacts: the fast lane takes the same slot in the score. */
export const GROUP_ORDER: readonly Group[] = ['E', 'X', 'EXPOSURE', 'SEV', 'SSVC', 'PRIOR', 'NOISE', 'INFO'];
const GROUP_BY_CHIP: Readonly<Record<string, Group>> = { 'fast.lane': 'EXPOSURE', 'edge.device': 'EXPOSURE' };
export const groupOf = (c: { id: string; family: Family }): Group => GROUP_BY_CHIP[c.id] ?? c.family;

/** A reason with the display group it is shown under. */
export interface GroupedReason {
  reason: Reason;
  /** True when the chip could have scored but a stronger chip in its scoring family won. */
  lost: boolean;
  /** For a lost chip: the chip that counted, when it is shown under another group. */
  wonElsewhere?: { id: string; group: Group };
}

/**
 * The CVE page's evidence sections, in GROUP_ORDER, unknowns left out. Points per section are
 * the sum of the reasons shown there, so the sections still add up to the score.
 */
export function groupReasons(reasons: readonly Reason[]): { group: Group; pts: number; scored: boolean; items: GroupedReason[] }[] {
  const shown = reasons.filter((r) => r.polarity !== 'unknown');
  return GROUP_ORDER.flatMap((g) => {
    const rs = shown.filter((r) => groupOf(r) === g);
    if (rs.length === 0) return [];
    const items = rs.map((r): GroupedReason => {
      const lost = r.points === 0 && r.polarity !== 'info' && r.family !== 'E';
      if (!lost) return { reason: r, lost };
      const won = shown.find((o) => o.family === r.family && o.points > 0 && o.polarity === 'up');
      return won && groupOf(won) !== g ? { reason: r, lost, wonElsewhere: { id: won.id, group: groupOf(won) } } : { reason: r, lost };
    });
    return [{ group: g, pts: rs.reduce((a, r) => a + r.points, 0), scored: rs.some((r) => r.polarity !== 'info'), items }];
  });
}

/** Why a chip shows 0, e.g. "counted 0: a stronger exploit chip won". */
export function lostNote(g: GroupedReason): string {
  if (g.reason.id === 'fast.lane') return 'counted 0: a stronger exploit chip won';
  if (g.wonElsewhere) return `counted 0: ${CHIP_BY_ID[g.wonElsewhere.id]?.short ?? g.wonElsewhere.id} under ${GROUP_META[g.wonElsewhere.group].label} won`;
  return 'counted 0: a stronger chip in this family won';
}

export const SOURCE_NAMES: Readonly<Record<SourceId, string>> = {
  cvelist: 'CVE List V5',
  'cisa-adp': 'CISA ADP',
  kev: 'CISA KEV',
  epss: 'EPSS',
  metasploit: 'Metasploit',
  nuclei: 'Nuclei',
  exploitdb: 'Exploit-DB',
  'poc-github': 'PoC-in-GitHub',
  'eu-kev': 'ENISA EU KEV',
  'circl-kev': 'CIRCL KEV',
  siberkapan: 'SiberKapan',
  osv: 'OSV.dev',
  computed: 'Computed',
};

/** Visual tone of a chip: exploitation is red, AI credit violet, otherwise by polarity. */
export type ChipTone = 'exploited' | 'up' | 'down' | 'info' | 'ai' | 'unknown';
export function chipTone(def: Pick<ChipDef, 'id' | 'family' | 'polarity'>): ChipTone {
  if (def.family === 'E') return 'exploited';
  if (def.id === 'ai.credit') return 'ai';
  return def.polarity;
}

export const chipDef = (id: string): ChipDef | undefined => CHIP_BY_ID[id];

/**
 * The headline and its reason, e.g. "Patch now" + "exploited, KEV due Oct 29": the same words as
 * link previews (shared/verdict.ts), with dates relative to the current year.
 */
export const verdict = (d: CveDetail, tier: Tier, knob: number): { head: string; reason: string } => sharedVerdict(d, tier, knob, new Date().getUTCFullYear());

/** A detail's tier at another knob: exploitation never depends on it, weaponization forces Likely. */
export function detailTier(d: CveDetail, knob: number): Tier {
  return tierFor(d.score.value, d.score.tier === 'exploited', d.exploits.metasploit.length > 0 || d.exploits.nuclei.length > 0, knob);
}
