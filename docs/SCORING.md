# Scoring methodology

Score model **v0.4.0** (v0.3.0 plus the `fast.lane` chip, +12 in the first 14 days for a network-reachable, automatable, total-impact CVE on an edge device or in a product already in KEV; see [Fast lane](#fast-lane). v0.3.0 added `x.early`, −3 for no exploit signal in the first 14 days, except on internet-facing edge devices; see [Cold start](#cold-start) and [Internet-facing edge devices](#internet-facing-edge-devices). v0.2.0 added the ENISA EU KEV and CIRCL catalog chips; see [Other known-exploited catalogs](#other-known-exploited-catalogs)). The single source of truth is [`shared/model.ts`](../shared/model.ts)
(chips and points) and [`pipeline/src/score.ts`](../pipeline/src/score.ts) (when each chip fires).
The site's Method page renders its chip table from the same file. If this document and the code
disagree, the code is right and this document has a bug.

CVErdict gives every CVE an **evidence score** from 0 to 100: how much public evidence there is
that the CVE is being exploited, or soon will be. It is an ordering for triage, not a probability,
and it knows nothing about your environment.

## Principles

1. **Evidence over severity.** CVSS measures how bad exploitation would be, not how likely it is.
   Half of all new CVEs are High or Critical, so severity is a small modifier here, not the core.
2. **Explainable by construction.** A score is a base plus a sum of reason chips. Every chip has a
   label, a source and, where possible, a link to the evidence. No machine learning, no LLM text.
3. **Correlated evidence counts once.** Within a family only the strongest chip counts: a Metasploit
   module, an Exploit-DB entry and five PoCs are one piece of evidence ("public exploit exists"),
   not seven.
4. **Confirmed exploitation dominates.** Once exploitation is confirmed, nothing else matters
   much; the score is floored at 90.
5. **Unknowns are shown, never imputed.** A missing CVSS score or SSVC assessment, a record that
   names no vendor and a source that could not be loaded are *unknown* chips worth 0 points, listed
   under "what we could not see" (a missing EPSS score is listed there too). Quiet means no
   evidence *yet*.
6. **Free public data only.** CVE List V5 (CNA and CISA-ADP containers), CISA KEV, ENISA's EU KEV,
   the CIRCL and SiberKapan catalogs, EPSS, Metasploit, Nuclei, Exploit-DB and PoC-in-GitHub. Nothing from NVD, which stopped enriching most CVEs in
   April 2026.

## The formula

```text
age        = days since datePublished
E chips    = kev.listed | ssvc.active | vendor.exploited (CVSS v4 E:A) | vendor.itw      (any → exploited)
X family   = max of: x.metasploit 34, x.nuclei 30, x.exploitdb 28, epss.high 27*, vendor.functional 24 (CVSS v3 E:F/E:H),
                     x.poc 20 (vetted ≥ 1), fast.lane 12†, ssvc.poc 10, vendor.poc 10 (E:P), epss.mid 8*
             * EPSS chips only when age ≥ 14 days (otherwise add info chip epss.cold if scored)
             † fast lane: age < 14, AV:N (CVSS v3/v4), (SSVC automatable and total, or no SSVC and CVSS ≥ 9.0),
               and (edge device or prior.product)
             if none, with every exploit source and EPSS loaded and no unvetted PoC repo:
                      x.none −14 when age ≥ 14, else x.early −3 (x.too_new, 0, on an edge device)
                      otherwise x.too_new (unknown, 0)
SEV        = sev.crit_net 13 (≥9.0 and AV:N) | sev.crit 6 (≥9.0) | sev.high 1 (7–8.9) | sev.low −13 (<7) | sev.none (unknown)
SSVC       = (ssvc.automatable 6 | ssvc.not_automatable −2) + (ssvc.total 8 | ssvc.partial −6) | ssvc.missing (unknown)
PRIOR      = prior.product 10 | prior.vendor 8 | prior.none −6 | prior.unknown (no vendor named, or KEV unavailable)
NOISE      = only if no E, X ≤ 0, no unvetted PoC repo and every exploit source and EPSS loaded:
             min of noise.hobby −20, noise.disputed −15, noise.wordpress −10, noise.kernel −8
             hobby: CNA text matches sourcecodester|code-projects|itsourcecode|phpgurukul|campcodes|kashipara|projectworlds
             wordpress: assigner ∈ {Wordfence, WPScan, Patchstack} or text matches /wordpress (plugin|theme)|for wordpress/i
             kernel: assigner = Linux and SSVC technical impact ≠ total
raw        = 15 + X + SEV + SSVC + PRIOR + NOISE
score      = E ? min(100, max(raw + 75, 90) + (ransomware Known ? 5 : 0)) : clamp(raw, 0, 100)
weaponized = x.metasploit or x.nuclei present
tier       = tierFor(score, E, weaponized, knob)          (shared/contract.ts)
INFO chips = ai.credit, batch, kev.due, kev.forensic, sev.adp, epss.cold, poc.hype, poc.unvetted, tag.eol, edge.device (0 points)
edge       = affected vendor/product (or CPE) in the curated list of shared/edge.ts, and AV:N when CVSS exists
```

Details that matter when you read a score:

- **The arithmetic adds up.** `reasons[]` holds every chip that fired, including the ones that
  lost within their family (shown with `points: 0`). For an exploited CVE, the winning E chip
  carries `min(100, max(raw + 75, 90)) − raw` (the +75, the floor and the cap) and `kev.ransomware`
  carries whatever of its +5 still fits under 100, so base + Σ points = score. For every other CVE
  base + Σ points = `raw` (`score.raw`), and the score is `raw` clamped to 0–100. Without
  exploitation `raw` is at most 86, so base + Σ points equals the score for every CVE except those
  with a negative `raw`, which score 0 (5,667 of the 17,526 CVEs in the 2026-10-26 run).
- **E chips are checked in catalogue order** (KEV, SSVC *active*, vendor CVSS, vendor text); the
  first that fires carries the points. `kev.listed` also fires from the KEV block CISA adds to the
  CVE record itself, so a KEV listing counts even if the KEV download failed.
- **Vendor exploit maturity** comes from the `E` metric in every CVSS v3/v4 vector the CNA itself
  published. Only v4 `E:A` (attacked) means exploited (`vendor.exploited`). v3 `E:F`/`E:H` say that
  functional or autonomous exploit code exists, which is weaponization, not attacks, so they give
  the X chip `vendor.functional` (+24). `E:P` means a proof of concept (`vendor.poc`). Vectors from
  VulDB are ignored because it stamps `E:P` on most of them.
- **Vendor "in the wild" text** is an English-description match, sentence by sentence, for phrases
  such as *exploited in the wild*, *aware of reports*, *limited, targeted attacks* or *may have been
  exploited*. A sentence does not count when a negation (*no*, *not*, *unaware*, *without* or a
  *n't* contraction) comes at most 60 characters before *exploit…* or *in the wild* in that same
  sentence. "There is no evidence that this vulnerability has been exploited in the wild" is
  negated; a negation in another sentence cancels nothing.
- **CVSS** prefers the CNA's v4.0, then v3.1, then v3.0. When the CNA gave none of those,
  CISA-ADP's score is used (v4.0, then v3.1, then v3.0) with the `sev.adp` info chip. A CNA v2-only
  score is displayed but scores as `sev.none`.
- **PRIOR** matches every affected vendor/product in the record (and, for KEV CVEs, the KEV entry's
  own vendor/product) against the KEV catalogue by canonical name. Vendor names are lower-cased and
  stripped of accents, punctuation, parentheses, a leading *The* and trailing legal-form or
  line-of-business words (*Inc*, *Corporation*, *Ltd*, *GmbH*, *Systems*, *Networks*, *Software*,
  *Foundation*, *Technologies* …), and a few renames are aliased (Zimbra → Synacor, NetScaler →
  Citrix, ManageEngine → Zoho, Hewlett Packard Enterprise → HPE). So "Juniper Networks" meets
  KEV's "Juniper" and "The Apache Software Foundation" meets "Apache". A name without an exact
  match falls back to the longest KEV vendor whose words it starts with ("Siemens Mobility" →
  Siemens), whole words only, so "Applied Signal" never matches Apple. Products are compared within
  the vendor, with a leading vendor name dropped ("Apache Tomcat" → Tomcat). Counts exclude the CVE
  being scored. A record that names no vendor gets `prior.unknown` (0), and so does every record
  when the KEV catalogue could not be loaded.
- **A missing source is unknown, not absent.** When a source has neither a fresh nor a cached
  copy, its silence is not evidence. Without KEV, PRIOR is `prior.unknown`. Without Metasploit,
  Nuclei, Exploit-DB, PoC-in-GitHub or EPSS, a CVE with no exploit chip gets `x.too_new` ("Exploit
  check incomplete") instead of `x.none`, and NOISE stays off. In the first 14 days EPSS does not
  score, so an EPSS outage alone does not stop `x.early`. The CVE page names the missing
  sources under "what we could not see".
- **Row chips.** List views carry up to four chip ids per CVE (`Row.c`), strongest first, positive
  chips before negative ones. `Row.r` lists every chip that fired, family losers included and
  unknowns left out, so filters also find a chip that is not in the top four.

## Chips and points

Generated from `shared/model.ts`. "Unknown" chips mark missing evidence and are worth 0.

### E: confirmed exploitation

Any of the first six puts the CVE in **Exploited**. The first that fires, in this order, carries the +75 and the floor of 90; the others are shown with 0. `kev.ransomware` adds +5 on top, still capped at 100.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `kev.listed` | CISA KEV | +75 | `kev` | Listed in CISA Known Exploited Vulnerabilities (or the CISA-ADP KEV block in the CVE record). |
| `eukev.listed` | EU KEV | +75 | `eu-kev` | Listed in ENISA’s EU Known Exploited Vulnerabilities catalog: ENISA or a national CSIRT of the EU CSIRTs Network reported exploitation. ENISA material, reproduced with acknowledgement. |
| `circl.listed` | CIRCL KEV | +75 | `circl-kev` | CIRCL (Computer Incident Response Center Luxembourg, the CERT for Luxembourg’s private sector) lists it as confirmed exploited in its own known-exploited catalog (CC0-1.0), with evidence beyond exploitation attempts. |
| `ssvc.active` | SSVC: active | +75 | `cisa-adp` | CISA Vulnrichment SSVC assessment says exploitation is active. |
| `vendor.exploited` | Vendor: exploited | +75 | `cvelist` | The CNA’s own CVSS v4 vector says the bug is being attacked (E:A). VulDB vectors are ignored. |
| `vendor.itw` | Vendor: in the wild | +75 | `cvelist` | The CNA description says the bug is exploited or “may have been exploited” in the wild. |
| `kev.ransomware` | Ransomware | +5 | `kev` | CISA marks known use in ransomware campaigns. The flag lags, so its absence means little. |

### X: exploit artifacts and prediction

Strongest one counts; the rest are shown with 0. `fast.lane` is the one X chip that is not an exploit sign: it marks a profile that attack tools exploit fast (see [Fast lane](#fast-lane)). `x.too_new` stands in for `x.none` or `x.early` when a PoC repo is still too new to vet or an exploit source could not be loaded, and for `x.early` on an [internet-facing edge device](#internet-facing-edge-devices).

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `x.metasploit` | Metasploit | +34 | `metasploit` | A Metasploit module exists. Also forces at least the Likely tier. |
| `x.nuclei` | Nuclei template | +30 | `nuclei` | A ProjectDiscovery Nuclei template exists, so it can be scanned for at internet scale. Forces at least Likely. |
| `x.exploitdb` | Exploit-DB | +28 | `exploitdb` | An Exploit-DB entry references this CVE. |
| `epss.high` | EPSS ≥ 10% | +27 | `epss` | EPSS gives ≥ 10% probability of exploitation activity in the next 30 days (only trusted after 14 days). |
| `x.poc` | PoC on GitHub | +20 | `poc-github` | At least one public proof-of-concept repo that passes basic vetting. Unverified code that may be malware. |
| `ssvc.poc` | SSVC: PoC | +10 | `cisa-adp` | CISA SSVC assessment says a public proof of concept exists. |
| `vendor.functional` | Vendor: working exploit | +24 | `cvelist` | The CNA’s CVSS v3 vector says functional or autonomous exploit code exists (E:F/E:H). That is weaponization, not proof of attacks: about a quarter of such CVEs reach KEV. VulDB vectors are ignored. |
| `vendor.poc` | Vendor: PoC | +10 | `cvelist` | The CNA’s CVSS vector says a proof of concept exists (E:P). VulDB vectors are ignored. |
| `epss.mid` | EPSS 1–10% | +8 | `epss` | EPSS between 1% and 10% (only trusted after 14 days). |
| `fast.lane` | Fast lane | +12 | `computed` | Less than 14 days old, attack vector Network, CISA SSVC automatable with total impact (or CVSS 9.0 or more while SSVC is not in yet), on an internet-facing edge device or a product already in CISA KEV. Attack tools now turn such bugs into exploits within hours or days, before exploit feeds see them, so this stands in for an exploit sign. The strongest X chip counts, so a real exploit replaces it. |
| `x.none` | No exploit yet | −14 | `computed` | Two weeks after publication there is still no public exploit and EPSS is below 1%. |
| `x.early` | No exploit yet (early) | −3 | `computed` | Less than 14 days old and no exploit signal yet. Weak evidence, so a small penalty: severity, SSVC and KEV history alone stay under the default evidence bar. Not applied to internet-facing edge devices, and replaced by the fast lane when that fires. |
| `x.too_new` | Too new | unknown | `computed` | No exploit chip, but absence is not settled: a PoC repo is too new to vet, an exploit source could not be loaded this run, or the CVE is an internet-facing edge device under 14 days old. |

### SEV: severity

CVSS base score from the CNA (v4.0 > v3.1 > v3.0), else CISA-ADP (v4.0 > v3.1 > v3.0). v2-only scores are shown but not scored.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `sev.crit_net` | Critical · network | +13 | `cvelist` | CVSS ≥ 9.0 and attack vector Network. |
| `sev.crit` | Critical | +6 | `cvelist` | CVSS ≥ 9.0, not network-reachable. |
| `sev.high` | High | +1 | `cvelist` | CVSS 7.0–8.9. Half of all new CVEs are High or Critical, so this barely moves the needle. |
| `sev.low` | Medium/Low | −13 | `cvelist` | CVSS below 7.0. |
| `sev.none` | No CVSS | unknown | `computed` | Neither the CNA nor CISA-ADP published a CVSS score. |

### SSVC: CISA decision points

The two decision points are independent, so they add.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `ssvc.automatable` | Automatable | +6 | `cisa-adp` | CISA SSVC: steps 1–4 of the kill chain can be automated (wormable / mass-exploitable). |
| `ssvc.not_automatable` | Not automatable | −2 | `cisa-adp` | CISA SSVC: exploitation cannot be reliably automated. |
| `ssvc.total` | Total impact | +8 | `cisa-adp` | CISA SSVC: full control of the affected component, or total information disclosure. |
| `ssvc.partial` | Partial impact | −6 | `cisa-adp` | CISA SSVC: limited control or information exposure. |
| `ssvc.missing` | No SSVC yet | unknown | `computed` | CISA has not published an SSVC assessment yet (usually arrives within a day). |

### PRIOR: KEV history of the vendor and product

Counts exclude the CVE itself. `prior.unknown` also covers a run in which the KEV catalogue could not be loaded.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `prior.product` | Product in KEV | +10 | `kev` | Other CVEs in this exact product are already in CISA KEV. Attackers return to the same targets. |
| `prior.vendor` | Vendor in KEV | +8 | `kev` | Other products from this vendor are in CISA KEV. |
| `prior.none` | Never in KEV | −6 | `kev` | Nothing from this vendor has ever been listed in CISA KEV. |
| `prior.unknown` | KEV history unknown | unknown | `computed` | The record names no vendor, or the KEV catalog could not be loaded this run, so the KEV history check could not run. |

### NOISE: low-value volume

Only applied when there is no exploitation and the X family is ≤ 0, and not while the absence of an exploit is still open (an unvetted PoC repo, or an exploit source or EPSS that could not be loaded). It does apply during the cold start. The most negative one counts.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `noise.hobby` | Tutorial project | −20 | `cvelist` | Student/tutorial code (SourceCodester, code-projects, PHPGurukul, …) that is rarely deployed. |
| `noise.disputed` | Disputed | −15 | `cvelist` | The CNA tagged this record as disputed. |
| `noise.wordpress` | WordPress plugin | −10 | `cvelist` | A WordPress plugin or theme. These are about 15% of all volume, and most have small install bases. |
| `noise.kernel` | Kernel bug-fix | −8 | `cvelist` | A Linux kernel CNA bug-fix CVE without total technical impact. |

### INFO: context (0 points)

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `ai.credit` | AI-credited | 0 | `cvelist` | The CNA credits an AI system or AI lab for the discovery. Information only: AI-found bugs are exploited at about the base rate. |
| `batch` | Batch release | 0 | `computed` | Published with 50+ other CVEs from the same CNA on the same day: a vendor patch day, or a bulk release by an aggregator CNA. |
| `kev.due` | KEV due | 0 | `kev` | Federal agencies must remediate by the KEV due date. |
| `kev.forensic` | Forensic triage | 0 | `kev` | CISA asks for forensic triage, not just patching (BOD 26-04). |
| `sev.adp` | CVSS from CISA | 0 | `cisa-adp` | The CNA gave no CVSS score; the CISA-ADP score is used instead. |
| `epss.cold` | EPSS (cold) | 0 | `epss` | EPSS score shown for context only: the CVE is too new for EPSS to be meaningful. |
| `poc.hype` | PoC hype | 0 | `poc-github` | More than 50 PoC repos appeared within a week. That measures attention, not weaponization, and fake PoCs often carry malware. |
| `poc.unvetted` | Unvetted PoC | 0 | `poc-github` | Only brand-new, unstarred PoC repos exist. Not counted until they age or gain stars. |
| `circl.suspected` | CIRCL: suspected | 0 | `circl-kev` | CIRCL lists exploitation as suspected, not confirmed (CC0-1.0). Information only. |
| `circl.attempts` | CIRCL: attempts | 0 | `circl-kev` | CIRCL lists it as confirmed in its known-exploited catalog (CC0-1.0), but the only evidence is exploitation attempts, such as hits on a sinkhole. Attempts are not proof that an attack worked: information only. |
| `honeypot.siberkapan` | Honeypot attempts | 0 | `siberkapan` | SiberKapan’s honeypot and web sensors in Turkey saw exploitation attempts (CC-BY-4.0). Attempts are not proof that an attack worked, and one sensor network gives too little data to set points: information only. |
| `edge.device` | Edge device | 0 | `computed` | An internet-facing edge device: VPN, firewall, load balancer, email gateway, file transfer, webmail, remote support, SD-WAN or edge router (curated list in shared/edge.ts, explained in docs/SCORING.md). These are often attacked before any exploit is public, so the early no-exploit penalty does not apply. |
| `tag.eol` | Unsupported product | 0 | `cvelist` | The product was unsupported when the CVE was assigned: there may be no patch. Replace or mitigate. |

## Other known-exploited catalogs

CISA KEV is not the only public list of exploited CVEs. v0.2.0 reads three more, chosen by two
rules: the licence must allow reuse (CC0, CC-BY, or an equivalent grant with attribution), and the
entries must assert exploitation, not just mention a CVE. Each chip names its catalog in the label,
with the licence where it asks for attribution.

| Catalog | Licence | Chip | Why that weight |
|---|---|---|---|
| [ENISA EU KEV](https://euvd.enisa.europa.eu/), from the EUVD KEV dump | ENISA legal notice: reproduction authorised with acknowledgement | `eukev.listed`, E family | Entries are exploitation reported by ENISA or a national CSIRT of the EU CSIRTs Network (CERT.PL, NCSC-NL, CSIRT-IE, CERT-AT, …), as successful exploitation or confirmed compromise. That is the same kind of claim as a CISA KEV listing, by the same kind of party, so it sets Exploited like KEV. |
| [CIRCL known exploited catalog](https://vulnerability.circl.lu/known-exploited-vulnerabilities-catalog/?catalog_uuid=1a89b78e-f703-45f3-bb86-59eb712668bd) | CC0-1.0 | `circl.listed` (status *confirmed*, evidence beyond attempts), E family; `circl.attempts` and `circl.suspected`, 0 points | CIRCL (Computer Incident Response Center Luxembourg) is the CERT for Luxembourg's private sector, communes and non-governmental entities. A *confirmed* entry with no evidence attached (CIRCL's own assertion) or with evidence of successful exploitation or a confirmed compromise is a CERT asserting exploitation in the wild, so it counts like KEV. A *confirmed* entry whose evidence is only `in_the_wild_attempts` (sinkhole hits, six of the 33 entries) is not: GCVE BCP-07 says confirmed attempts are not confirmed successful exploitation, which is the reason `honeypot.siberkapan` gets no points, so it is information only (`circl.attempts`). *Suspected* is by definition not a confirmation, and there are two such entries: too few to measure a likelihood ratio, so information only. |
| [SiberKapan honeypot catalog](https://siberkapan.org/kev-catalog), through CIRCL | CC-BY-4.0 | `honeypot.siberkapan`, 0 points | Exploitation *attempts* against one sensor network in Turkey. BCP-07 is explicit that attempts do not imply success and that honeypot volume is not higher confidence. Its 14 CVEs are all old, 13 already in CISA KEV and listed there years before SiberKapan saw them, so there is no data to estimate a likelihood ratio without look-ahead bias. Information only until there is. |

Left out: CIRCL's copy of CISA KEV (a duplicate of `kev`); the Shadowserver and Previdian catalogs
and CIRCL's sightings (no licence stated anywhere we could find; Previdian's terms also forbid use
in a competing catalog and CIRCL measures it as a 99.9% mirror of CISA KEV).

**Dates.** A listing is dated only by a date the catalog can vouch for: EU KEV's own listing date,
or BCP-07 `asserted_at` ("mirrors date added in KEV lists"), never `first_seen_at`, which may be
estimated after the fact. The EUVD dump gives one date per CVE, the earliest across CISA KEV and EU
KEV: it is EU KEV's own date for an EU-only entry, or when it is before the CISA date; for the other
EU entries (listed on the CISA day or later) the chip is undated. The backtest counts a listing in
the strict figures only when that date is before the KEV listing day, an undated one only with
undated evidence, and one dated on the listing day or later in neither. An undated EU entry is in
that last group too: the dump shows it was listed on the CISA day or later, so it cannot have come
before the KEV listing.

**Effect**, measured offline on the frozen inputs of the backtest of Nov 13, 2026 (`--now
2026-11-13T20:00Z`, catalogs as of Nov 18; listings dated later are ignored):

- In the 30-day window (16,910 CVEs) one CVE gains a chip, CVE-2026-110936 (`eukev.listed`,
  already in CISA KEV), and no CVE changes tier or score. Over the 18,862 CVEs that had a detail
  record before old catalog-only CVEs were kept (window, KEV, woke up): `eukev.listed` 66,
  `circl.listed` 20, `honeypot.siberkapan` 13, `circl.attempts` 3 (CVE-2014-8361, CVE-2021-35394,
  CVE-2023-28771), `circl.suspected` 2, all on CVEs CISA KEV also lists,
  so no tier changes.
- Old CVEs that only EU KEV or CIRCL list as exploited are now kept like CISA KEV's (see
  [Catalog-only CVEs outside the window](#catalog-only-cves-outside-the-window)): on the same
  inputs, 19 more CVEs get a detail record (16 EU KEV, 3 CIRCL), all Exploited, none in CISA KEV.
  Two of them woke up in the period (CVE-2015-0279, EU KEV Oct 25; CVE-2026-6692, CIRCL Nov 10).
  No other CVE changes score or tier.
- In the backtest, EU KEV listed 8 of the 130 recent KEV additions before CISA did, which CVErdict
  had missed: strict 48 → 56 of 130 (36.9% → 43.1%), with undated evidence 94 → 96 (EU entries
  the dump dates on the CISA day count in neither). Old CVEs are
  unchanged (15 and 17 of 20). The evidence bar at 40, 50 and 60 catches 56 → 64, 48 → 56 and
  36 → 46. Alert volume over the 180 days: 1,809 → 1,813 CVEs.

## Tiers and the evidence bar

```ts
function tierFor(score, exploited, weaponized, knob) {
  if (exploited) return 'exploited';
  if (weaponized || score >= knob) return 'likely';
  if (score >= 25) return 'watch';       // WATCH_FLOOR
  return 'quiet';
}
```

| Tier | Rule | Reading |
|---|---|---|
| **Exploited** | any E chip | Confirmed exploitation. Patch now. |
| **Likely next** | Metasploit module or Nuclei template, or score ≥ the evidence bar | Exploitation is plausible soon. Patch within days. |
| **Watch** | 25 ≤ score < the evidence bar | Some evidence. Revisit. |
| **Quiet** | score < 25 | No evidence yet. Quiet ≠ safe. |

The **evidence bar** (parameter `knob`) is the score a CVE needs to count as Likely next: a score
threshold. It defaults to 50. The site keeps the setting in `?knob=` and re-derives every tier
client-side with the same `tierFor()` from [`shared/contract.ts`](../shared/contract.ts). The tier
stored in the data files is the one at the default bar. CVEs with a Metasploit module or Nuclei template
are Likely next at any setting, because they can be exploited, or scanned for, at internet scale today.
Vendors and products on your watchlist always show on Today, whatever the bar.

**Range.** The site's dial runs from 35 to 65 in steps of 5, with presets *Broad* 40, *Balanced* 50
and *Strict* 60. The pipeline (`--knob`), the data files and the MCP server still accept 30 to 80
(`KNOB_MIN` and `KNOB_MAX`), so nothing that already uses them breaks. A `?knob=` link outside 35 to
65 opens at the nearest end: `?knob=30` at 35, `?knob=80` at 65. Three landmarks follow from the
weights in [`shared/model.ts`](../shared/model.ts):

- **From 40 up, a CVE that has gone two weeks with no exploit sign can never pass.** The most such a
  CVE can score is 38: 15 base + 13 critical network bug + 14 SSVC (total, automatable) + 10 product
  in KEV − 14 for no exploit yet.
- **From 50 up (the default), every CVE listed has some exploit sign.** Without one (a PoC, Exploit-DB, EPSS, CISA or the vendor saying an
  exploit exists, exploitation, Metasploit or Nuclei), the most a CVE can score is 49: 52 from the
  profile, − 3 for no exploit signal yet in its first two weeks. The exceptions: a CVE whose
  question is still open (a PoC repo too new to vet, or an exploit source down this run) or that
  is on an [internet-facing edge device](#internet-facing-edge-devices) in its first 14 days can
  reach 52, and a CVE in the [fast lane](#fast-lane) can reach 64 (15 + 12 + 13 + 14 + 10).
  From 65 up there is no exception.
- **80 is the most a CVE can score without being exploited or having a Metasploit module or Nuclei
  template:** 15 + 28 Exploit-DB + 13 + 14 + 10. At 80 nothing passes on score; only the CVEs that
  always pass are left.

The ends of the old range did little that was useful. In the 2026-11-10 02:47 UTC window, going
from 35 to 30 added 761 CVEs (25 more a day), most of them the 418 that score exactly 30 with no
exploit evidence at all, for 4 more early catches in the backtest below. Below 35 the site also has
to download every row (`index.json`, 6.1 MB) instead of `signal.json` (0.4 MB). From 65 to 80 the
list changed by 16 CVEs, and 65 and 70 gave the same list. Between 35 and 65 each step of 5 cuts the
list by a quarter to a half, and every stop gives a different count. Steps of 5 are enough: about
97% of scores are even, so an odd setting behaves like the next even one.

## Cold start

A CVE's first two weeks are the hardest: exploit feeds lag publication by days, and EPSS has little
to go on (78 of the 333 CVEs published on 2026-10-26, 23%, had an EPSS score that day). For the first **14 days** after
publication (`COLD_START_DAYS`):

- EPSS does not score. If a score exists it is shown as the `epss.cold` info chip.
- Silence is weak evidence: instead of `x.none` (−14) the CVE gets `x.early` (−3), and the CVE
  page says how many days remain. While a PoC repo is too new to vet or an exploit source is down,
  it gets `x.too_new`, an unknown worth 0, as after the cold start.
- On an [internet-facing edge device](#internet-facing-edge-devices) silence says even less, so
  the CVE gets `x.too_new` (0) instead of `x.early`, plus the `edge.device` info chip.

Everything else, including exploitation, exploit artifacts, severity, SSVC and prior, counts from
day 0. A critical network bug from a vendor with KEV history scores at most 47 before any exploit
signal (49 when this exact product is in KEV but SSVC does not say automatable and total), just
under the default bar: it is at the top of Watch, and any exploit signal (a vetted
PoC, Exploit-DB, CISA or the vendor saying a PoC exists) lifts it to Likely next. See
CVE-2026-105016 in the [examples below](#worked-examples). On an edge device the same profile
scores 50 or 52 and is Likely next from day 0. A network-reachable, automatable, total-impact CVE
on an edge device or in a product already in KEV is in the [fast lane](#fast-lane) instead: +12
until day 14, Likely next from day 0.

**Why −3 (v0.3.0).** Up to v0.2.0 silence in the first two weeks was worth 0, and that profile
scored 50 or 52: Likely next on severity, SSVC and KEV history alone. In the 2026-11-20 16:47 UTC
window that was 171 of the 401 Likely CVEs, 6 of the 6 that passed in the last 24 hours, and none
had any exploit sign. Every one of them falls back to Watch on day 14 unless an exploit sign
appears, because `x.none` then takes 14 points. In the 180-day backtest to 2026-11-18 the profile alone
flagged 1 of the 134 recent KEV additions before CISA listed it (1 or 2 with undated evidence). −3 is the smallest penalty that keeps the
strongest such profile (52) under the default bar. In that window it took Likely from 401 to 238
(Exploited or Likely: about 14 a day to about 9); the 8 that stay have a PoC repo too new to vet.
With the edge device exemption Likely is 257 (about 9.5 a day): 19 more of the 171 stay, all on
edge devices, and the backtest keeps its one profile catch, CVE-2026-85102 (Check Point Quantum
Security Gateway).

## Internet-facing edge devices

VPN gateways, firewalls, load balancers and the like exist to take connections from the internet.
Attackers find them with a scan and often exploit a new bug in days, before anyone publishes an
exploit, so a quiet first two weeks says little about them. A CVE whose affected product is on the
list below does not get `x.early`: it keeps `x.too_new` (unknown, 0) and gets the `edge.device`
info chip (0 points), so the CVE page says why. After day 14 nothing differs: no exploit signal is
`x.none` (−14) like for any other CVE. The list is in [`shared/edge.ts`](../shared/edge.ts).

**How it matches.** Every affected vendor and product in the CNA record, and any CPE 2.3 name in it,
is lower-cased and reduced to plain words ("PAN-OS" → "pan os"). The vendor must be the entry's
vendor; a product name alone never matches, so "Acme Connect Secure" is not Ivanti. A combined
product ("FortiOS, FortiProxy", "IOS and IOS XE") is split and each part is checked. A part that
names a client, app, agent, desktop app or management tools is endpoint software and never matches
("BIG-IP Edge Client", "GlobalProtect App", "FortiClient", "Zimbra Desktop"). Fortinet's hosted
services ("FortiManager Cloud", "FortiGate Cloud") never match: Fortinet patches them, not you. With a CVSS score, the attack vector must be Network.

**Why this list.** Each product faces the internet by design and has at least one CISA KEV entry
from 2021-11-20 to 2026-11-20, or shares its code with one that does (Policy Secure and ZTA
Gateway with Connect Secure, FortiGate, FortiProxy and FortiADC with FortiOS). Counts are KEV
entries in those five years, matched by KEV's own vendor and product, or by the CVE record when
KEV says "Multiple Products". Together they are 284 of the 1,499 entries.

| Kind | Products (KEV entries) |
|---|---|
| VPN and remote access | Ivanti Connect Secure, Policy Secure and ZTA Gateway, with Pulse Secure (9), Ivanti Cloud Services Appliance (5), Ivanti EPMM and Sentry (10), Palo Alto PAN-OS with GlobalProtect (13), SonicWall SMA and SRA (11), Array Networks AG (2), Cisco Expressway (1) |
| Firewalls and UTM | Fortinet FortiOS, FortiGate and FortiProxy (16), FortiWeb (4), FortiManager (1), Cisco ASA and FTD (12), SonicWall SonicOS (4), Check Point Security Gateway (3), Juniper Junos OS and ScreenOS (8), Zyxel ATP, USG, USG FLEX, VPN and ZyWALL (5), Sophos Firewall, XG and SG UTM (5), WatchGuard Firebox (4) |
| Load balancers and ADCs | Citrix NetScaler ADC and Gateway (16), F5 BIG-IP (6), Fortinet FortiADC, Progress Kemp LoadMaster (2), Ivanti Virtual Traffic Manager (1) |
| Email and web gateways | Barracuda Email Security Gateway (3), Cisco Secure Email (3), Fortinet FortiMail (2), Sophos Web Appliance (1) |
| File transfer | Progress MOVEit Transfer (1) and WS_FTP Server (1), Fortra GoAnywhere MFT (2), Cleo Harmony, VLTrader and LexiCom (2), CrushFTP (3), Wing FTP Server (2), SolarWinds Serv-U (3), IBM Aspera Faspex (2), Gladinet CentreStack and Triofox (4), Citrix ShareFile Storage Zones Controller (2) |
| Webmail | Zimbra Collaboration (19), Roundcube Webmail (10), Microsoft Exchange Server (9), SmarterTools SmarterMail (3) |
| Remote support | BeyondTrust Remote Support and PRA (4), ConnectWise ScreenConnect (4), SimpleHelp (4) |
| SD-WAN | Cisco Catalyst SD-WAN (9), Arista and VMware VeloCloud (4), Versa Director and Concerto (2) |
| Edge routers | Cisco IOS XE and IOS XR, whose web UI and management plane face the network edge (31), Cisco RV series VPN routers (9), MikroTik RouterOS (5), DrayTek Vigor (4) |

Choices worth stating:

- **Webmail is in.** A mail server's web interface (Zimbra, Roundcube, SmarterMail, Exchange's
  Outlook on the web, EWS and ActiveSync) faces the internet by design, and these are some of the
  most listed products in KEV. Exchange Online is not: Microsoft patches it, not you.
- **FortiManager is in, FortiAnalyzer is not.** Managed FortiGates reach FortiManager over FGFM,
  often across the internet, and that port was mass-exploited in 2024. FortiAnalyzer,
  FortiSandbox, FortiAuthenticator and FortiClient EMS are internal or endpoint products.
- **Management consoles are out** unless they face the internet by design: Cisco FMC, Check Point
  Security Management, F5 BIG-IQ, SonicWall GMS, WatchGuard Dimension, Ivanti EPM and Cisco ISE
  sit inside the network. Cisco Secure Email and Web Manager is in, as part of Cisco Secure Email.
- **Home routers, cameras and NAS are out.** D-Link, TP-Link, Netgear, Tenda and similar products
  are in KEV too, but they bring a large volume of CVEs that are never exploited, many for devices
  past end of life, and they rarely reach the bar without an exploit sign anyway.
- **Business software that is often published is out**: SharePoint, Confluence, Oracle E-Business
  Suite, SAP NetWeaver, vCenter, video conferencing (TrueConf) and PBX servers. They are not edge
  devices by design, and adding them would turn the list into "popular software".
- **No KEV entry, not yet.** Edge products with no KEV entry in the five years (Barracuda
  CloudGen Firewall and WAF, SonicWall Email Security, Juniper Session Smart Router) are left out
  until they have one.
- **Classic Cisco IOS is out**, IOS XE and IOS XR are in. Most classic IOS entries in KEV are bugs
  from 2017 and 2018 listed in bulk in 2022, and IOS XE now runs Cisco's edge routers.

**What it changes** (2026-11-20 16:47 UTC window, 16,612 CVEs): 233 window CVEs are on edge
devices. Of the 171 Likely CVEs that had no exploit sign, 19 stay Likely because of the exemption
(Citrix NetScaler 8, F5 BIG-IP 6, Fortinet 4: FortiOS, FortiMail twice and FortiManager, and
SmarterMail 1). In the 180-day backtest, CVE-2026-85102 (Check Point Quantum Security Gateway, 13
days old when CISA listed it) stays caught on its profile alone. These counts match on affected vendor and
product. Adding the CNA's CPE names, read from the raw CVE List records, changes none of them.

**Proposing an addition.** Open an issue or pull request that changes `EDGE_ENTRIES` in
[`shared/edge.ts`](../shared/edge.ts) and adds the product's real CNA spellings to
[`shared/edge.test.ts`](../shared/edge.test.ts), with near misses for the same vendor's endpoint or
management products. Say why the product faces the internet by design, and link its KEV entries:
at least one in the last five years is the bar used here. The list changes scores, so a change to
it is a new score model.

## Fast lane

**The rule (v0.4.0).** A CVE gets the `fast.lane` chip (+12, X family) when all of these hold:

1. It is less than 14 days old (the cold start).
2. Its CVSS v3 or v4 score (from the CNA, else CISA-ADP) has attack vector **Network**.
3. CISA SSVC says **automatable** and **total** technical impact. While SSVC is not in yet (it often
   arrives days after publication), a CVSS base score of **9.0 or more** stands in for it. Once SSVC
   is in, it decides: "not automatable" or "partial" turns the fast lane off.
4. It is exposed: an [internet-facing edge device](#internet-facing-edge-devices), or this exact
   **product** is already in CISA KEV (`prior.product`). A vendor with KEV history is not enough.

The label names exactly which criteria fired, for example "Fast lane: network, automatable, total
impact, on an edge device" or "Fast lane: network, CVSS 9.8, no SSVC yet, product in KEV", and the
CVE page verdict says "fast lane, no public exploit yet". The chip takes the place of `x.early`
and of `x.too_new` on an edge device. The strongest X chip counts, so a vetted PoC (+20) or any
stronger artifact replaces it, and a positive X chip switches noise penalties off as usual. On day
14 it ends: with no exploit sign by then the CVE gets `x.none` (−14) like any other.

**Why.** These are the criteria of CISA's
[BOD 26-04, Prioritizing Security Updates Based on Risk](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk):
patch within days when there is evidence of exploitation, automatability, high technical impact
or public exposure. We took those terms from a summary of the directive (cisa.gov did not let us
fetch it), so read the directive itself before relying on the wording. The reason to act on them
before an exploit is public is speed: attack tools that use AI agents now turn a public reproducer
or a patch into a working exploit within hours for a meaningful share of bugs, and those exploits
often never reach Exploit-DB or GitHub. To be candid, the fast lane targets that automation speed.
It is not evidence that anyone is attacking the CVE, and most fast-lane CVEs will never be.

**What it changes** (2026-11-23 16:47 UTC window, 16,337 CVEs, 30 days; same recount method as
for [x.early](#cold-start), from the live rows and receipts). 90 window CVEs fit the profile, 57
of them under 14 days old:

| | v0.3.0 | v0.4.0 |
|---|--:|--:|
| Likely next at 50 | 252 | 272 |
| Exploited or Likely next, share of new CVEs | 1.70% | 1.82% |
| Per day at 40 / 50 / 60 | 21.6 / 9.3 / 4.7 | 21.7 / 9.9 / 5.9 |
| Passed in the last 7 days | 34 | 51 |
| Backtest, strict, recent KEV additions caught (of 137) | 59 (43%) | 65 (47%) |
| Backtest, with undated evidence (of 137) | 99 | 100 (estimate) |
| Backtest, old CVEs (of 15), strict / undated | 10 / 12 | 10 / 12 |

The 20 new Likely next CVEs in the window are Oracle WebLogic Server (6) and PeopleSoft
PeopleTools, Apache Tomcat (3) and Roller, N-able N-central (2), JetBrains TeamCity, PHP, Splunk
Enterprise, Fortinet FortiMail, Mozilla Firefox, Mitel MiCollab and Synology DSM. The 6 new strict
backtest catches were all critical network bugs with no SSVC yet at the cutoff, flagged on profile
alone: IBM Aspera Faspex, Arista VeloCloud Orchestrator and ConnectWise ScreenConnect (edge
devices), N-able N-central, JFrog Artifactory and Metabase (product in KEV). No catch is lost. For
two of them (VeloCloud, ScreenConnect) CISA's SSVC now says "not automatable", dated within a day
of the listing, so the backtest cannot tell whether it was in before. If it was, the fast lane was
off and those two are not caught: 63 to 65 of 137.

**What we tried and did not ship.** Exempting the profile from `x.early` with no points, or adding
+6, catches nothing new in the backtest: the CVEs that matter are the ones without SSVC yet, which
score 38 and need +12 to reach 50. Counting a vendor with KEV history as exposure (not just the
product) adds 118 more Likely next CVEs in the window (share 2.55%, +0.85 points) for no extra
backtest catch, mostly bulk releases from big vendors (Apache TomEE, SAP, Microsoft). Requiring a
public fix (a reference tagged `patch` or `vendor-advisory`) loses the ScreenConnect catch for 7
fewer CVEs in the window, so it is not required. Keeping the +12 after day 14 adds 23 more Likely
next CVEs with no catch.

## PoC vetting

PoC-in-GitHub lists every public repository that claims to be a proof of concept, and plenty of
them are empty, wrong or malware. Before a repository counts:

- forks are dropped, and records that are not PUBLISHED are ignored;
- a repository is **vetted** once it has at least 2 stars **or** was created at least 3 days ago;
- `x.poc` (+20) needs at least one vetted repository. If there are only unvetted ones, the CVE gets
  the `poc.unvetted` info chip until they age or gain stars. The question is open meanwhile, so
  after the cold start such a CVE gets `x.too_new` ("Not settled") instead of `x.none`, and no
  noise penalty;
- more than 50 repositories created within 7 days of the first one is **hype** (`poc.hype`, info):
  a measure of attention, not of weaponization, and a common way to spread fake PoCs.

PoC links are always labelled "unverified, may be malware", and the site never renders their content.

## Noise heuristics

A large share of the volume is code that is rarely deployed or reports that are contested. Noise
chips push those down, but **only when there is no exploitation and no positive exploit artifact**
(the X family settled on ≤ 0). Any real evidence, or an exploit check that could not finish,
switches the penalty off. Only the most negative noise chip counts.

| Chip | Points | Fires when |
|---|--:|---|
| `noise.hobby` | −20 | The record mentions SourceCodester, code-projects, itsourcecode, PHPGurukul, CampCodes, Kashipara or ProjectWorlds: student and tutorial projects |
| `noise.disputed` | −15 | The CNA tagged the record `disputed` |
| `noise.wordpress` | −10 | The CNA is Wordfence, WPScan or Patchstack, or the text says "WordPress plugin/theme" or "for WordPress" |
| `noise.kernel` | −8 | The CNA is the Linux kernel and CISA's SSVC technical impact is not *total*: the kernel CNA assigns a CVE to most bug fixes |

## Worked examples

From the run of 2026-10-26 19:30 UTC. Info chips other than EPSS are left out.

**CVE-2026-96951** · Windows Shell Security Feature Bypass · KEV, day 13

```text
   15  base
  +24  Vendor CVSS: working exploit code exists (E:F)
   +1  High 8.8 · network (v3.1)
   +8  CISA SSVC: total technical impact
   −2  CISA SSVC: not automatable
  +10  Product in KEV (×174): Microsoft Windows
    0  EPSS 9.8% · 95th pct · day 13, too new to trust   (info)
  ───
   56  raw
  +44  CISA KEV · added Oct 13 · due Oct 16        (raw + 75 = 131, capped at 100)
    0  CISA SSVC: exploitation active · Oct 8      (lost to KEV within E)
  ───
  100  Exploited
```

Microsoft's own vector says `E:F`: working exploit code exists. That is the X chip
`vendor.functional`, not exploitation: without the KEV listing and CISA's SSVC *active*, this CVE
would score 56, Likely next.

**CVE-2026-105016** · Microsoft QUIC Remote Code Execution · day 13

```text
   15  base
  +13  Critical 9.8 · network (v3.1)
   +8  CISA SSVC: total technical impact
   +6  CISA SSVC: automatable
   +8  Vendor in KEV (×390): Microsoft
   −3  No exploit signal yet: day 13 of 14, exploit feeds lag
    0  EPSS 1.7% · 76th pct · day 13, too new to trust   (info)
  ───
   47  Watch at the default evidence bar (Likely next at Broad, 40)
```

Up to v0.2.0, without the −3, this scored 50: Likely next on its profile alone. One day later the
cold start ends. If EPSS is still at 1% or more, `epss.mid` (+8) lifts the score to 58; below 1%
and with no public exploit, `x.none` (−14) drops it to 36, which is Watch.

**CVE-2013-10076** · ExtUtils::Typemaps::STL::Vector (Perl) · day 16

```text
   15  base
  −14  No public exploit after 16 days · EPSS 0.38%
   +1  High 7.5 · network (v3.1)
   +6  CISA SSVC: automatable
   −6  CISA SSVC: partial technical impact
    0  No CNA score; CISA-ADP CVSS 7.5 used        (info)
    0  No affected vendor named, KEV history not checked   (unknown)
  ───
    2  Quiet
```

The record names no vendor, so PRIOR is `prior.unknown`, worth 0, and the CVE page lists it under
what we could not see.

## Calibration

Measured with `npm run calibrate` (`scripts/calibrate.ts`, which runs the pipeline's own ingest and
`scoreCve()`) on the frozen inputs of the **2026-10-26 19:30 UTC** run. Treat every recall number
here as an **optimistic upper bound**: the evidence was observed in October, after the fact.
Exploit modules, PoCs and vendor statements for a CVE listed in KEV in March may have appeared only
*after* the listing, often because of it, and the KEV prior includes listings that came later. This
look-ahead bias is why the points were shrunk 15–30% from the raw likelihood ratios, and why the
recall figures below would be lower in real time.

**Selectivity.** In the 2026-11-10 02:47 UTC run, 301 of the 17,076 CVEs published in the 30-day
window (1.8%) passed at the default bar: 28 Exploited and 273 Likely next, about 10 a day. That is
1 in 57 instead of all of them.

**Recall without the answer key.** To see whether the score finds exploited CVEs *before* KEV
does, all 272 CVEs added to KEV in 2026 were re-scored with the direct evidence removed: their own
KEV entry and the CISA-ADP KEV block, SSVC *active* (lowered to *poc* when a public exploit
artifact exists, else *none*; every one of the 272 was *active*, and the choice changes no score)
and their EPSS score. The KEV prior still comes from the rest of the catalogue. At the default bar (50) the
remaining signals put them in:

| Tier (KEV, SSVC *active* and EPSS hidden) | 2026 KEV additions | Share |
|---|--:|--:|
| Exploited, on vendor evidence alone (16 description, 12 CVSS v4 `E:A`) | 28 | 10.3% |
| Likely next | 174 | 64.0% |
| Watch | 27 | 9.9% |
| Quiet | 43 | 15.8% |

**Evidence bar sensitivity.** Each stop of the site's dial on the window of the
**2026-11-10 02:47 UTC** run (17,076 CVEs over 30 days), on two measures:

- **KEV recall, upper bound:** the method above, run with `npm run calibrate` on that run's inputs:
  all 288 CVEs added to KEV in 2026, re-scored with KEV, SSVC *active* and EPSS hidden.
- **Caught early:** the time-matched backtest on the Receipts page (below). Of the 120 recent CVEs
  CISA added to KEV in the 180 days to Nov 3, how many the setting would have listed before CISA did,
  using only what was known the day before. At 50 this matched the `receipts.json` of that run (37 of 120).

| Evidence bar | Pass in 30 days | About a day | KEV recall, upper bound (of 288) | Caught early (of 120) |
|--:|--:|--:|--:|--:|
| 35 | 1,066 (6.2%) | 36 | 235 (81.6%) | 63 |
| 40 | 604 (3.5%) | 20 | 226 (78.5%) | 46 |
| 45 | 416 (2.4%) | 14 | 220 (76.4%) | 39 |
| **50** (default) | **301 (1.8%)** | **10** | **216 (75.0%)** | **37** |
| 55 | 166 (1.0%) | 5.5 | 175 (60.8%) | 29 |
| 60 | 111 (0.65%) | 3.7 | 172 (59.7%) | 19 |
| 65 | 81 (0.47%) | 2.7 | 160 (55.6%) | 17 |

The 28 Exploited CVEs and the 37 with a Metasploit module or Nuclei template (65 in all) pass at
any setting, which is why the counts flatten out above 60.

On the upper-bound measure the default sits at the knee. Going from 50 to 45 adds 115 CVEs for 4
more of the 288 KEV CVEs; going to 55 removes 135 CVEs but loses 41. The drop starts right at 51:
the KEV CVEs that score exactly 50 or 52 are mostly vendor or product KEV history + High + SSVC
total − not automatable + a PoC on GitHub. Much of the window at 50 is the cold start: a critical
network bug with SSVC total and automatable from a vendor with KEV history scores 50 for its first
two weeks under v0.2.0 (47 from v0.3.0), then most fall to 36 (the pattern of CVE-2026-105016
above). These figures are from a v0.2.0 run; rerun `npm run calibrate` for v0.3.0. Because the knee is one
exact sum of weights, a small weight change can move it: re-check it after any change.

On the stricter backtest there is no sharp knee: recall falls steadily as the bar rises, and 50 is
a fair middle. The counts move from run to run; the site computes them live.

### Receipts: the real-time record and a time-matched backtest

The recall above is an upper bound by construction. The [Receipts page](https://cverdict.dev/receipts)
(`v1/receipts.json`, [DATA.md](DATA.md#receiptsjson)) measures the same question in two stricter ways,
with the same rules for CVErdict (Exploited or Likely next at the default evidence bar, 50), "CVSS 7 or more" and "EPSS
10% or more":

- **The forward log** (`pipeline/src/receipts.ts`) records, on every run, when each method first
  flagged each window CVE, and later whether that came before CISA's KEV listing. It never fills
  in anything from before it started; the Receipts page shows how many listings it has judged.
- **The backtest** (`pipeline/src/backtest.ts`, `npm run backtest`) re-scores every KEV addition
  of the last 180 days with the evidence of the day before its listing wherever the source dates
  it, and leaves undated evidence out (its "strict" figures) or adds today's value ("with undated
  evidence", usually the higher figure). It is hindsight and labelled as such.

The backtest computed 2026-11-03 05:47 UTC (178 KEV additions since 2026-05-07; 38 left out
because the CVE was published on or after its listing day, 1 without a published record). PoC
repos count in the strict figures only when they were created and last pushed before the listing
day:

| Published up to 2 years before the listing (120) | Flagged before KEV (strict) | With undated evidence |
|---|--:|--:|
| CVErdict | 37 (30.8%) | 84 (70.0%) |
| CVSS 7 or more | 65 (54.2%) | 108 (90.0%) |
| EPSS 10% or more | 17 (14.2%) | 17 (14.2%) |

For the 19 CVEs published more than 2 years before their listing: CVErdict 15 (17 with undated
evidence), CVSS 7 or more 3 (19), EPSS 10% or more 12. Over the same 180 days, with today's evidence, CVErdict
flags 2.6% of the 68,169 new CVEs, CVSS 7 or more 52.2% and EPSS 10% or more 0.2% (`backtest.volume`
in that run's receipts.json; the count moves with the 180-day range).

The strict figures are unflattering for CVErdict, and for a known reason: CISA rewrites its part of
the CVE record when it lists a CVE, so the strict variant cannot use CISA's SSVC exploitation value
or CISA-ADP CVSS for almost any of these CVEs, nor an SSVC assessment stamped on the day before the
listing (CISA often dates its listing update that way), and a CNA record changed after the listing
loses its CVSS too. CVSS 7 or more catches more of these CVEs before KEV, at twenty times the alert volume.
The forward log is the measurement that settles it.

## Catalog-only CVEs outside the window

Resolved blind spot: a CVE listed only in ENISA EU KEV or CIRCL's catalog (not in CISA KEV) used to
be scored only while it was in the 30-day window or woke up, so an older one never showed. The
pipeline now keeps every CVE with an exploited listing in those catalogs whatever its age, the same
way it keeps every CISA KEV CVE: it gets a CVE page in the Exploited tier, and a first listing
dated in the last 30 days is a Woke Up signal (`catalog`) once the CVE has left the window, and a "what changed" arrival
when it is under 7 days old. Only the listings that set Exploited count: every EU KEV listing, and a
CIRCL entry that is *confirmed* with evidence beyond attempts. SiberKapan, CIRCL *suspected* and
CIRCL attempts-only listings stay information only and never pull a CVE in. These CVEs have no CISA
due date, so they are not on the KEV Clock, in `kev.json`, `feeds/kev.xml` or `feeds/kev-due.ics`.
A dated exploited listing before the period also counts as older evidence for Woke Up, like an
earlier CISA KEV listing: such a CVE was awake already.

Measured on the frozen inputs of Nov 13, 2026 (offline, `--now 2026-11-13T20:00Z`, catalogs as of
Nov 18 without listings dated later): 19 CVEs are added, 18,862 → 18,881 detail records (16 by EU
KEV, 3 by CIRCL). The 19 shards that gain one grow by 0.4 to 1.2 KB gzip each (largest shard
unchanged at 54 KB of 80 KB), `woke.json` +0.3 KB (23 of 64 KB), `packages.json` +0.7 KB (118 of 256
KB, 5 more CVEs), `feeds/woke.xml` +0.3 KB; the file count is unchanged at 271 of 300. Run time is
unchanged within run-to-run noise (four runs each, 37.6 to 43.7 s before and 36.6 to 43.6 s after,
as the pipeline reports it); the extra work is one set union and 19 more records to normalise.

| CVE | Catalog | Listed | Vendor / product | Published |
|---|---|---|---|---|
| CVE-2011-4085 | EU KEV | 2025-07-14 | Red Hat JBoss Enterprise Application Platform | 2012-11-23 |
| CVE-2015-0279 | EU KEV | 2026-10-25 (woke up) | Red Hat JBoss RichFaces | 2015-03-26 |
| CVE-2015-7501 | EU KEV | 2025-07-14 | Red Hat JBoss (Apache Commons Collections) | 2017-11-09 |
| CVE-2025-25231 | EU KEV | 2025-09-09 | Omnissa Workspace ONE UEM | 2025-08-11 |
| CVE-2025-59719 | EU KEV | 2026-01-27 | Fortinet FortiWeb | 2025-12-09 |
| CVE-2026-39813 | CIRCL | 2026-06-22 | Fortinet FortiSandbox | 2026-04-14 |
| CVE-2026-40477 | EU KEV | 2026-10-10 | Thymeleaf | 2026-04-17 |
| CVE-2026-40478 | EU KEV | 2026-10-10 | Thymeleaf | 2026-04-17 |
| CVE-2026-41679 | EU KEV | 2026-08-17 | Paperclip (paperclipai) | 2026-04-23 |
| CVE-2026-6692 | CIRCL | 2026-11-10 (woke up) | Slider Revolution (WordPress) | 2026-05-07 |
| CVE-2026-41901 | EU KEV | 2026-10-10 | Thymeleaf | 2026-05-12 |
| CVE-2026-49049 | EU KEV | 2026-07-10 | JoomShaper Helix3 (Joomla) | 2026-06-29 |
| CVE-2026-19478 | CIRCL | 2026-08-21 | GitLab | 2026-08-17 |
| CVE-2026-74232 | EU KEV | 2026-08-27 | Zbtlink routers (MQWrt) | 2026-08-27 |
| CVE-2026-74233 | EU KEV | 2026-08-27 | Zbtlink routers (MQWrt) | 2026-08-27 |
| CVE-2026-58400 | EU KEV | 2026-09-02 | GeoNetwork | 2026-09-03 |
| CVE-2026-63219 | EU KEV | 2026-09-02 | GeoNetwork | 2026-09-03 |
| CVE-2026-67276 | EU KEV | 2026-09-05 | MikroTik RouterOS | 2026-09-05 |
| CVE-2026-85103 | EU KEV | 2026-09-25 | Check Point Quantum Security Gateway | 2026-09-09 |

## Known blind spots

- **Vendor zero-days without artifacts.** Targeted exploitation of edge devices and enterprise
  software is often disclosed with a patch, with no public exploit, no "in the wild" wording in the
  CVE record and no KEV entry for days. These sit in Watch, or even Quiet, until KEV or the vendor
  catches up. Products on the [edge device list](#internet-facing-edge-devices) skip the early
  no-exploit penalty, which helps only when the profile is strong; the list is curated, so a new
  edge product is missed until someone adds it. The [fast lane](#fast-lane) lifts the strongest
  exposed profiles to Likely next on day 0, but only for edge devices and products already in KEV.
- **KEV lag.** KEV lists exploitation CISA can confirm, which typically trails the first reports by
  days to weeks, and it covers products US federal agencies care about. Not in KEV ≠ not exploited.
- **EPSS cold start.** EPSS needs time to observe a CVE; it is ignored for 14 days and missing for
  most CVEs on day 0, so the first two weeks rely on artifacts, severity, SSVC and prior.
- **WordPress premium plugins.** The WordPress noise penalty assumes small install bases. Popular
  premium plugins and themes with large installed bases are demoted until exploit evidence appears
  (which then switches the penalty off).
- **Name matching.** The KEV prior compares canonical vendor and product names. CNAs spell
  products inconsistently, so a prior can be missed (no bonus) or matched too broadly: the
  whole-word prefix fallback reads "Progress Planner" as Progress and "Linux Mint" as Linux, and an
  umbrella vendor's KEV history covers all of its products.
- **Text heuristics are English.** The "in the wild" pattern and the noise patterns read the English
  description only.

## Proposing a weight change

Weights live in [`shared/model.ts`](../shared/model.ts); the thresholds that decide whether a chip
fires (EPSS bands, CVSS bands, PoC vetting, hype) live in [`pipeline/src/score.ts`](../pipeline/src/score.ts),
and the tier thresholds (the API's evidence bar range, Watch floor) in [`shared/contract.ts`](../shared/contract.ts);
the site's narrower dial range is in [`site/src/state.ts`](../site/src/state.ts).
A change to either is a new score model.

1. Open an issue first if the change is large, with the reasoning and the evidence behind it.
2. In the pull request, bump `SCORE_MODEL` (minor version for re-weighting, major for a new family
   or a changed rule) and update the unit tests and this document.
3. Include a **calibration diff**: the output of `npm run calibrate -- --offline --now <same instant>`
   before and after the change (tiers and pass rate at evidence bars 35 to 65, KEV recall measured as above,
   the largest batch), plus the 20 CVEs whose tier moved the most, with their chips (compare two
   `npm run pipeline -- --offline --now <same instant>` outputs).
4. Explain what the change gets wrong as well as what it gets right. A weight that only helps
   look-ahead (evidence that appears after exploitation is known) will be declined.

Disagreeing with a single score is just as welcome: use the "Disagree?" button on the CVE page, or
the [issue template](https://github.com/markusweldon/cverdict/issues/new?template=disagree-with-a-score.yml).
