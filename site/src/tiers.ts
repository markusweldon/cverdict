/** Presentation metadata for tiers, chip families and sources, plus the plain-language verdict. */
import { WATCH_FLOOR, tierFor, type CveDetail, type Family, type Reason, type SourceId, type Tier } from '../../shared/contract';
import { CHIP_BY_ID, type ChipDef } from '../../shared/model';
import { fmtDate, fmtPct } from './format';

export const TIER_META: Readonly<Record<Tier, { label: string; verdict: string; blurb: string }>> = {
  exploited: { label: 'Exploited', verdict: 'Patch now', blurb: 'Confirmed exploitation: CISA KEV, CISA SSVC “active”, or the vendor says so.' },
  likely: { label: 'Likely', verdict: 'Likely next', blurb: 'A public exploit artifact, or enough evidence to clear the knob.' },
  watch: { label: 'Watch', verdict: 'Watch', blurb: `Some evidence, below the knob but above the watch floor (${WATCH_FLOOR}).` },
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

/** The headline and its reason, e.g. "Patch now" + "exploited, KEV due Oct 29". */
export function verdict(d: CveDetail, tier: Tier, knob: number): { head: string; reason: string } {
  const head = TIER_META[tier].verdict;
  const strongest = (family: Family) => d.reasons.find((r) => r.family === family && r.polarity === 'up' && r.points > 0) ?? d.reasons.find((r) => r.family === family && r.polarity === 'up');
  if (tier === 'exploited') {
    if (d.kev) return { head, reason: `exploited, KEV due ${fmtDate(d.kev.due_date)}` };
    if (d.ssvc?.exploitation === 'active') return { head, reason: 'exploited: CISA SSVC says exploitation is active' };
    return { head, reason: 'exploited: the vendor reports exploitation' };
  }
  if (tier === 'likely') {
    const x = strongest('X');
    return { head, reason: x ? artifactPhrase(x, d) : `score ${d.score.value} clears the knob (${knob})` };
  }
  if (tier === 'watch') return { head, reason: `score ${d.score.value}: below the knob (${knob}), above the watch floor (${WATCH_FLOOR})` };
  return { head, reason: 'no evidence yet (quiet ≠ safe)' };
}

function artifactPhrase(r: Reason, d: CveDetail): string {
  switch (r.id) {
    case 'x.metasploit':
      return 'Metasploit module';
    case 'x.nuclei':
      return 'Nuclei template — scannable at internet scale';
    case 'x.exploitdb':
      return 'Exploit-DB entry';
    case 'epss.high':
    case 'epss.mid':
      return d.epss ? `EPSS ${fmtPct(d.epss.score)} chance of exploitation in 30 days` : 'high EPSS';
    case 'x.poc':
      return `public proof of concept (${d.exploits.poc.vetted} vetted repo${d.exploits.poc.vetted === 1 ? '' : 's'})`;
    default:
      return CHIP_BY_ID[r.id]?.short ?? r.label;
  }
}

/** A detail's tier at another knob: exploitation never depends on it, weaponization forces Likely. */
export function detailTier(d: CveDetail, knob: number): Tier {
  return tierFor(d.score.value, d.score.tier === 'exploited', d.exploits.metasploit.length > 0 || d.exploits.nuclei.length > 0, knob);
}
