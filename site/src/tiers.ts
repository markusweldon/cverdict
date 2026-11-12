/** Presentation metadata for tiers, chip families and sources, plus the plain-language verdict. */
import { WATCH_FLOOR, tierFor, type CveDetail, type Family, type SourceId, type Tier } from '../../shared/contract';
import { CHIP_BY_ID, type ChipDef } from '../../shared/model';
import { verdict as sharedVerdict } from '../../shared/verdict';

export const TIER_META: Readonly<Record<Tier, { label: string; verdict: string; blurb: string }>> = {
  exploited: { label: 'Exploited', verdict: 'Patch now', blurb: 'Confirmed exploitation: CISA KEV, CISA SSVC “active”, or the vendor says so.' },
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

export const SOURCE_NAMES: Readonly<Record<SourceId, string>> = {
  cvelist: 'CVE List V5',
  'cisa-adp': 'CISA ADP',
  kev: 'CISA KEV',
  epss: 'EPSS',
  metasploit: 'Metasploit',
  nuclei: 'Nuclei',
  exploitdb: 'Exploit-DB',
  'poc-github': 'PoC-in-GitHub',
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
