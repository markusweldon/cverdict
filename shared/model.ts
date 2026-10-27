/**
 * The scoring model: every chip, its family and its points. Single source of truth for the
 * pipeline (which applies it) and the site (which renders the methodology table from it).
 *
 * Points are roughly 20·log10(likelihood ratio of later KEV listing), shrunk 15–30% for
 * look-ahead bias, so +20 points ≈ 10× the odds. See docs/SCORING.md for the derivation,
 * calibration and known blind spots. Changing a number here changes SCORE_MODEL.
 */
import type { Family, Polarity, SourceId } from './contract';

export const SCORE_MODEL = 'v0.1.0';

export const BASE_POINTS = 15;
/** Added to the raw score when any E-family chip fires… */
export const EXPLOITED_BONUS = 75;
/** …and the result is floored here. */
export const EXPLOITED_FLOOR = 90;
/** Extra points for KEV knownRansomwareCampaignUse = Known (exploited tier only). */
export const RANSOMWARE_BONUS = 5;
/** Below this age (days since publication) EPSS and "no exploit yet" are not trusted. */
export const COLD_START_DAYS = 14;
/** A (cna, publish date) group at least this large is a patch-day batch. */
export const BATCH_MIN = 50;

export interface ChipDef {
  id: string;
  family: Family;
  polarity: Polarity;
  points: number;
  source: SourceId;
  /** Short label for list rows (≤ 22 chars). */
  short: string;
  /** One-line explanation for the methodology page and tooltips. */
  explain: string;
}

const c = (
  id: string,
  family: Family,
  polarity: Polarity,
  points: number,
  source: SourceId,
  short: string,
  explain: string,
): ChipDef => ({ id, family, polarity, points, source, short, explain });

export const CHIPS: readonly ChipDef[] = [
  // E — confirmed exploitation. Any one puts the CVE in the `exploited` tier.
  c('kev.listed', 'E', 'up', EXPLOITED_BONUS, 'kev', 'CISA KEV', 'Listed in CISA Known Exploited Vulnerabilities (or the CISA-ADP KEV block in the CVE record).'),
  c('ssvc.active', 'E', 'up', EXPLOITED_BONUS, 'cisa-adp', 'SSVC: active', 'CISA Vulnrichment SSVC assessment says exploitation is active.'),
  c('vendor.exploited', 'E', 'up', EXPLOITED_BONUS, 'cvelist', 'Vendor: exploited', 'The CNA’s own CVSS v4 vector says the bug is being attacked (E:A). VulDB vectors are ignored.'),
  c('vendor.itw', 'E', 'up', EXPLOITED_BONUS, 'cvelist', 'Vendor: in the wild', 'The CNA description says the bug is exploited or “may have been exploited” in the wild.'),
  c('kev.ransomware', 'E', 'up', RANSOMWARE_BONUS, 'kev', 'Ransomware', 'CISA marks known use in ransomware campaigns. The flag lags, so its absence means little.'),

  // X — public exploit artifacts and exploit prediction. Strongest one counts.
  c('x.metasploit', 'X', 'up', 34, 'metasploit', 'Metasploit', 'A Metasploit module exists. Also forces at least the Likely tier.'),
  c('x.nuclei', 'X', 'up', 30, 'nuclei', 'Nuclei template', 'A ProjectDiscovery Nuclei template exists, so it can be scanned for at internet scale. Forces at least Likely.'),
  c('x.exploitdb', 'X', 'up', 28, 'exploitdb', 'Exploit-DB', 'An Exploit-DB entry references this CVE.'),
  c('epss.high', 'X', 'up', 27, 'epss', 'EPSS ≥ 10%', 'EPSS gives ≥ 10% probability of exploitation activity in the next 30 days (only trusted after 14 days).'),
  c('x.poc', 'X', 'up', 20, 'poc-github', 'PoC on GitHub', 'At least one public proof-of-concept repo that passes basic vetting. Unverified code — may be malware.'),
  c('ssvc.poc', 'X', 'up', 10, 'cisa-adp', 'SSVC: PoC', 'CISA SSVC assessment says a public proof of concept exists.'),
  c('vendor.functional', 'X', 'up', 24, 'cvelist', 'Vendor: working exploit', 'The CNA’s CVSS v3 vector says functional or autonomous exploit code exists (E:F/E:H). That is weaponization, not proof of attacks: about a quarter of such CVEs reach KEV. VulDB vectors are ignored.'),
  c('vendor.poc', 'X', 'up', 10, 'cvelist', 'Vendor: PoC', 'The CNA’s CVSS vector says a proof of concept exists (E:P). VulDB vectors are ignored.'),
  c('epss.mid', 'X', 'up', 8, 'epss', 'EPSS 1–10%', 'EPSS between 1% and 10% (only trusted after 14 days).'),
  c('x.none', 'X', 'down', -14, 'computed', 'No exploit yet', 'Two weeks after publication there is still no public exploit and EPSS is below 1%.'),
  c('x.too_new', 'X', 'unknown', 0, 'computed', 'Too new', 'No exploit chip, but absence is not settled: the CVE is less than 14 days old, a PoC repo is too new to vet, or an exploit source could not be loaded this run.'),

  // SEV — CVSS base score as published by the CNA (or CISA-ADP when the CNA gave none).
  c('sev.crit_net', 'SEV', 'up', 13, 'cvelist', 'Critical · network', 'CVSS ≥ 9.0 and attack vector Network.'),
  c('sev.crit', 'SEV', 'up', 6, 'cvelist', 'Critical', 'CVSS ≥ 9.0, not network-reachable.'),
  c('sev.high', 'SEV', 'up', 1, 'cvelist', 'High', 'CVSS 7.0–8.9. Half of all new CVEs are High or Critical, so this barely moves the needle.'),
  c('sev.low', 'SEV', 'down', -13, 'cvelist', 'Medium/Low', 'CVSS below 7.0.'),
  c('sev.none', 'SEV', 'unknown', 0, 'computed', 'No CVSS', 'Neither the CNA nor CISA-ADP published a CVSS score.'),

  // SSVC — CISA Vulnrichment decision points (these two add).
  c('ssvc.automatable', 'SSVC', 'up', 6, 'cisa-adp', 'Automatable', 'CISA SSVC: steps 1–4 of the kill chain can be automated (wormable / mass-exploitable).'),
  c('ssvc.not_automatable', 'SSVC', 'down', -2, 'cisa-adp', 'Not automatable', 'CISA SSVC: exploitation cannot be reliably automated.'),
  c('ssvc.total', 'SSVC', 'up', 8, 'cisa-adp', 'Total impact', 'CISA SSVC: full control of the affected component, or total information disclosure.'),
  c('ssvc.partial', 'SSVC', 'down', -6, 'cisa-adp', 'Partial impact', 'CISA SSVC: limited control or information exposure.'),
  c('ssvc.missing', 'SSVC', 'unknown', 0, 'computed', 'No SSVC yet', 'CISA has not published an SSVC assessment yet (usually arrives within a day).'),

  // PRIOR — has this vendor/product been exploited before?
  c('prior.product', 'PRIOR', 'up', 10, 'kev', 'Product in KEV', 'Other CVEs in this exact product are already in CISA KEV. Attackers return to the same targets.'),
  c('prior.vendor', 'PRIOR', 'up', 8, 'kev', 'Vendor in KEV', 'Other products from this vendor are in CISA KEV.'),
  c('prior.none', 'PRIOR', 'down', -6, 'kev', 'Never in KEV', 'Nothing from this vendor has ever been listed in CISA KEV.'),
  c('prior.unknown', 'PRIOR', 'unknown', 0, 'computed', 'KEV history unknown', 'The record names no vendor, or the KEV catalog could not be loaded this run, so the KEV history check could not run.'),

  // NOISE — only applied when there is no exploitation and no exploit artifact. Strongest (most negative) counts.
  c('noise.hobby', 'NOISE', 'down', -20, 'cvelist', 'Tutorial project', 'Student/tutorial code (SourceCodester, code-projects, PHPGurukul, …) that is rarely deployed.'),
  c('noise.disputed', 'NOISE', 'down', -15, 'cvelist', 'Disputed', 'The CNA tagged this record as disputed.'),
  c('noise.wordpress', 'NOISE', 'down', -10, 'cvelist', 'WordPress plugin', 'A WordPress plugin or theme — about 15% of all volume; most have small install bases.'),
  c('noise.kernel', 'NOISE', 'down', -8, 'cvelist', 'Kernel bug-fix', 'A Linux kernel CNA bug-fix CVE without total technical impact.'),

  // INFO — context, 0 points.
  c('ai.credit', 'INFO', 'info', 0, 'cvelist', 'AI-credited', 'The CNA credits an AI system or AI lab for the discovery. Information only: AI-found bugs are exploited at about the base rate.'),
  c('batch', 'INFO', 'info', 0, 'computed', 'Batch release', 'Published with 50+ other CVEs from the same CNA on the same day: a vendor patch day, or a bulk release by an aggregator CNA.'),
  c('kev.due', 'INFO', 'info', 0, 'kev', 'KEV due', 'Federal agencies must remediate by the KEV due date.'),
  c('kev.forensic', 'INFO', 'info', 0, 'kev', 'Forensic triage', 'CISA asks for forensic triage, not just patching (BOD 26-04).'),
  c('sev.adp', 'INFO', 'info', 0, 'cisa-adp', 'CVSS from CISA', 'The CNA gave no CVSS score; the CISA-ADP score is used instead.'),
  c('epss.cold', 'INFO', 'info', 0, 'epss', 'EPSS (cold)', 'EPSS score shown for context only: the CVE is too new for EPSS to be meaningful.'),
  c('poc.hype', 'INFO', 'info', 0, 'poc-github', 'PoC hype', 'More than 50 PoC repos appeared within a week. That measures attention, not weaponization — and fake PoCs often carry malware.'),
  c('poc.unvetted', 'INFO', 'info', 0, 'poc-github', 'Unvetted PoC', 'Only brand-new, unstarred PoC repos exist. Not counted until they age or gain stars.'),
  c('tag.eol', 'INFO', 'info', 0, 'cvelist', 'Unsupported product', 'The product was unsupported when the CVE was assigned: there may be no patch — replace or mitigate.'),
];

export const CHIP_BY_ID: Readonly<Record<string, ChipDef>> = Object.fromEntries(CHIPS.map((d) => [d.id, d]));

export function chip(id: string): ChipDef {
  const d = CHIP_BY_ID[id];
  if (!d) throw new Error(`unknown chip id: ${id}`);
  return d;
}
