# Scoring methodology

Score model **v0.1.0**. The single source of truth is [`shared/model.ts`](../shared/model.ts)
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
6. **Free public data only.** CVE List V5 (CNA and CISA-ADP containers), CISA KEV, EPSS, Metasploit,
   Nuclei, Exploit-DB and PoC-in-GitHub. Nothing from NVD, which stopped enriching most CVEs in
   April 2026.

## The formula

```text
age        = days since datePublished
E chips    = kev.listed | ssvc.active | vendor.exploited (CVSS v4 E:A) | vendor.itw      (any → exploited)
X family   = max of: x.metasploit 34, x.nuclei 30, x.exploitdb 28, epss.high 27*, vendor.functional 24 (CVSS v3 E:F/E:H),
                     x.poc 20 (vetted ≥ 1), ssvc.poc 10, vendor.poc 10 (E:P), epss.mid 8*
             * EPSS chips only when age ≥ 14 days (otherwise add info chip epss.cold if scored)
             if none: x.none −14 when age ≥ 14, every exploit source and EPSS loaded, and no unvetted PoC repo;
                      else x.too_new (unknown, 0)
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
INFO chips = ai.credit, batch, kev.due, kev.forensic, sev.adp, epss.cold, poc.hype, poc.unvetted, tag.eol (0 points)
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
  check incomplete") instead of `x.none`, and NOISE stays off. The CVE page names the missing
  sources under "what we could not see".
- **Row chips.** List views carry up to four chip ids per CVE (`Row.c`), strongest first, positive
  chips before negative ones. `Row.r` lists every chip that fired, family losers included and
  unknowns left out, so filters also find a chip that is not in the top four.

## Chips and points

Generated from `shared/model.ts`. "Unknown" chips mark missing evidence and are worth 0.

### E — confirmed exploitation

Any of the first four puts the CVE in **Exploited**. The first that fires, in this order, carries the +75 and the floor of 90; the others are shown with 0. `kev.ransomware` adds +5 on top, still capped at 100.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `kev.listed` | CISA KEV | +75 | `kev` | Listed in CISA Known Exploited Vulnerabilities (or the CISA-ADP KEV block in the CVE record). |
| `ssvc.active` | SSVC: active | +75 | `cisa-adp` | CISA Vulnrichment SSVC assessment says exploitation is active. |
| `vendor.exploited` | Vendor: exploited | +75 | `cvelist` | The CNA’s own CVSS v4 vector says the bug is being attacked (E:A). VulDB vectors are ignored. |
| `vendor.itw` | Vendor: in the wild | +75 | `cvelist` | The CNA description says the bug is exploited or “may have been exploited” in the wild. |
| `kev.ransomware` | Ransomware | +5 | `kev` | CISA marks known use in ransomware campaigns. The flag lags, so its absence means little. |

### X — exploit artifacts and prediction

Strongest one counts; the rest are shown with 0. `x.too_new` also stands in for `x.none` after the cold start when a PoC repo is still too new to vet or an exploit source could not be loaded.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `x.metasploit` | Metasploit | +34 | `metasploit` | A Metasploit module exists. Also forces at least the Likely tier. |
| `x.nuclei` | Nuclei template | +30 | `nuclei` | A ProjectDiscovery Nuclei template exists, so it can be scanned for at internet scale. Forces at least Likely. |
| `x.exploitdb` | Exploit-DB | +28 | `exploitdb` | An Exploit-DB entry references this CVE. |
| `epss.high` | EPSS ≥ 10% | +27 | `epss` | EPSS gives ≥ 10% probability of exploitation activity in the next 30 days (only trusted after 14 days). |
| `x.poc` | PoC on GitHub | +20 | `poc-github` | At least one public proof-of-concept repo that passes basic vetting. Unverified code — may be malware. |
| `ssvc.poc` | SSVC: PoC | +10 | `cisa-adp` | CISA SSVC assessment says a public proof of concept exists. |
| `vendor.functional` | Vendor: working exploit | +24 | `cvelist` | The CNA’s CVSS v3 vector says functional or autonomous exploit code exists (E:F/E:H). That is weaponization, not proof of attacks: about a quarter of such CVEs reach KEV. VulDB vectors are ignored. |
| `vendor.poc` | Vendor: PoC | +10 | `cvelist` | The CNA’s CVSS vector says a proof of concept exists (E:P). VulDB vectors are ignored. |
| `epss.mid` | EPSS 1–10% | +8 | `epss` | EPSS between 1% and 10% (only trusted after 14 days). |
| `x.none` | No exploit yet | −14 | `computed` | Two weeks after publication there is still no public exploit and EPSS is below 1%. |
| `x.too_new` | Too new | unknown | `computed` | No exploit chip, but absence is not settled: the CVE is less than 14 days old, a PoC repo is too new to vet, or an exploit source could not be loaded this run. |

### SEV — severity

CVSS base score from the CNA (v4.0 > v3.1 > v3.0), else CISA-ADP (v4.0 > v3.1 > v3.0). v2-only scores are shown but not scored.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `sev.crit_net` | Critical · network | +13 | `cvelist` | CVSS ≥ 9.0 and attack vector Network. |
| `sev.crit` | Critical | +6 | `cvelist` | CVSS ≥ 9.0, not network-reachable. |
| `sev.high` | High | +1 | `cvelist` | CVSS 7.0–8.9. Half of all new CVEs are High or Critical, so this barely moves the needle. |
| `sev.low` | Medium/Low | −13 | `cvelist` | CVSS below 7.0. |
| `sev.none` | No CVSS | unknown | `computed` | Neither the CNA nor CISA-ADP published a CVSS score. |

### SSVC — CISA decision points

The two decision points are independent, so they add.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `ssvc.automatable` | Automatable | +6 | `cisa-adp` | CISA SSVC: steps 1–4 of the kill chain can be automated (wormable / mass-exploitable). |
| `ssvc.not_automatable` | Not automatable | −2 | `cisa-adp` | CISA SSVC: exploitation cannot be reliably automated. |
| `ssvc.total` | Total impact | +8 | `cisa-adp` | CISA SSVC: full control of the affected component, or total information disclosure. |
| `ssvc.partial` | Partial impact | −6 | `cisa-adp` | CISA SSVC: limited control or information exposure. |
| `ssvc.missing` | No SSVC yet | unknown | `computed` | CISA has not published an SSVC assessment yet (usually arrives within a day). |

### PRIOR — KEV history of the vendor and product

Counts exclude the CVE itself. `prior.unknown` also covers a run in which the KEV catalogue could not be loaded.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `prior.product` | Product in KEV | +10 | `kev` | Other CVEs in this exact product are already in CISA KEV. Attackers return to the same targets. |
| `prior.vendor` | Vendor in KEV | +8 | `kev` | Other products from this vendor are in CISA KEV. |
| `prior.none` | Never in KEV | −6 | `kev` | Nothing from this vendor has ever been listed in CISA KEV. |
| `prior.unknown` | KEV history unknown | unknown | `computed` | The record names no vendor, or the KEV catalog could not be loaded this run, so the KEV history check could not run. |

### NOISE — low-value volume

Only applied when there is no exploitation and the X family is ≤ 0, and not while the absence of an exploit is still open (an unvetted PoC repo, or an exploit source or EPSS that could not be loaded). It does apply during the cold start. The most negative one counts.

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `noise.hobby` | Tutorial project | −20 | `cvelist` | Student/tutorial code (SourceCodester, code-projects, PHPGurukul, …) that is rarely deployed. |
| `noise.disputed` | Disputed | −15 | `cvelist` | The CNA tagged this record as disputed. |
| `noise.wordpress` | WordPress plugin | −10 | `cvelist` | A WordPress plugin or theme — about 15% of all volume; most have small install bases. |
| `noise.kernel` | Kernel bug-fix | −8 | `cvelist` | A Linux kernel CNA bug-fix CVE without total technical impact. |

### INFO — context (0 points)

| Chip | Short label | Points | Source | Meaning |
|---|---|--:|---|---|
| `ai.credit` | AI-credited | 0 | `cvelist` | The CNA credits an AI system or AI lab for the discovery. Information only: AI-found bugs are exploited at about the base rate. |
| `batch` | Batch release | 0 | `computed` | Published with 50+ other CVEs from the same CNA on the same day: a vendor patch day, or a bulk release by an aggregator CNA. |
| `kev.due` | KEV due | 0 | `kev` | Federal agencies must remediate by the KEV due date. |
| `kev.forensic` | Forensic triage | 0 | `kev` | CISA asks for forensic triage, not just patching (BOD 26-04). |
| `sev.adp` | CVSS from CISA | 0 | `cisa-adp` | The CNA gave no CVSS score; the CISA-ADP score is used instead. |
| `epss.cold` | EPSS (cold) | 0 | `epss` | EPSS score shown for context only: the CVE is too new for EPSS to be meaningful. |
| `poc.hype` | PoC hype | 0 | `poc-github` | More than 50 PoC repos appeared within a week. That measures attention, not weaponization — and fake PoCs often carry malware. |
| `poc.unvetted` | Unvetted PoC | 0 | `poc-github` | Only brand-new, unstarred PoC repos exist. Not counted until they age or gain stars. |
| `tag.eol` | Unsupported product | 0 | `cvelist` | The product was unsupported when the CVE was assigned: there may be no patch — replace or mitigate. |

## Tiers and the knob

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
| **Likely next** | Metasploit module or Nuclei template, or score ≥ knob | Exploitation is plausible soon. Patch within days. |
| **Watch** | 25 ≤ score < knob | Some evidence. Revisit. |
| **Quiet** | score < 25 | No evidence yet. Quiet ≠ safe. |

The **knob** is the score a CVE needs to count as Likely next. It defaults to 50 and ranges from 30
to 80; the site offers presets *Tight* 60, *Default* 50 and *Wide* 40, keeps the setting in
`?knob=`, and re-derives every tier client-side with the same `tierFor()` from
[`shared/contract.ts`](../shared/contract.ts). The tier stored in the data files is the one at the
default knob. Weaponized CVEs (Metasploit or Nuclei) are Likely next at any knob, because they can
be exploited, or scanned for, at internet scale today. Vendors and products on your watchlist
bypass the knob entirely.

## Cold start

A CVE's first two weeks are the hardest: exploit feeds lag publication by days, and EPSS has little
to go on (78 of the 333 CVEs published on 2026-10-26, 23%, had an EPSS score that day). For the first **14 days** after
publication (`COLD_START_DAYS`):

- EPSS does not score. If a score exists it is shown as the `epss.cold` info chip.
- Silence is not evidence: instead of `x.none` (−14) the CVE gets `x.too_new`, an unknown worth 0,
  and the CVE page says how many days remain.

Everything else, including exploitation, exploit artifacts, severity, SSVC and prior, counts from
day 0. So a critical network bug from a vendor with KEV history can reach Likely next before any
exploit feed has caught up, as CVE-2026-105016 does on day 13 in the
[example below](#worked-examples).

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
    0  EPSS 9.8% · 95th pct · day 13 — too new to trust   (info)
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
    0  Too new: day 13 of 14 — exploit feeds lag
    0  EPSS 1.7% · 76th pct · day 13 — too new to trust   (info)
  ───
   50  Likely next at the default knob
```

One day later the cold start ends. If EPSS is still at 1% or more, `epss.mid` (+8) lifts the score
to 58; below 1% and with no public exploit, `x.none` (−14) drops it to 36, which is Watch.

**CVE-2013-10076** · ExtUtils::Typemaps::STL::Vector (Perl) · day 16

```text
   15  base
  −14  No public exploit after 16 days · EPSS 0.38%
   +1  High 7.5 · network (v3.1)
   +6  CISA SSVC: automatable
   −6  CISA SSVC: partial technical impact
    0  No CNA score; CISA-ADP CVSS 7.5 used        (info)
    0  No affected vendor named — KEV history not checked   (unknown)
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

**Selectivity.** Of all 15,790 CVEs published in the 30-day window, **363 (2.3%)** pass at knob
50: 27 Exploited and 336 Likely next. That is 1 in 43 instead of all of them.

**Recall without the answer key.** To see whether the score finds exploited CVEs *before* KEV
does, all 272 CVEs added to KEV in 2026 were re-scored with the direct evidence removed: their own
KEV entry and the CISA-ADP KEV block, SSVC *active* (lowered to *poc* when a public exploit
artifact exists, else *none*; every one of the 272 was *active*, and the choice changes no score)
and their EPSS score. The KEV prior still comes from the rest of the catalogue. At knob 50 the
remaining signals put them in:

| Tier (KEV, SSVC *active* and EPSS hidden) | 2026 KEV additions | Share |
|---|--:|--:|
| Exploited, on vendor evidence alone (16 description, 12 CVSS v4 `E:A`) | 28 | 10.3% |
| Likely next | 174 | 64.0% |
| Watch | 27 | 9.9% |
| Quiet | 43 | 15.8% |

**Knob sensitivity.** Pass rate of the window's CVEs against recall of the 2026 KEV additions
(Exploited + Likely next, with KEV, SSVC *active* and EPSS hidden):

| Knob | New CVEs passing | KEV recall |
|--:|--:|--:|
| 40 | 4.1% (643) | 77.6% (211) |
| 45 | 3.0% (468) | 75.7% (206) |
| **50** (default) | **2.3% (363)** | **74.3% (202)** |
| 55 | 0.8% (123) | 59.9% (163) |
| 60 | 0.5% (78) | 58.8% (160) |

The default sits at the knee. Going from 50 to 45 adds about 30% more volume for 1.5 points of
recall (4 more of 272); going to 55 cuts the volume by two-thirds but also 14 points of recall.
Much of that step is the cold start: 238 window CVEs score exactly 50 or 52. All 58 Likely-next
CVEs of Microsoft's Oct 13 batch score 50, most with the pattern of CVE-2026-105016 above (critical
network bug, SSVC total and automatable, a vendor with KEV history, too new for EPSS).

### Receipts: the real-time record and a time-matched backtest

The recall above is an upper bound by construction. The [Receipts page](https://cverdict-psi.vercel.app/receipts)
(`v1/receipts.json`, [DATA.md](DATA.md#receiptsjson)) measures the same question in two stricter ways,
with the same rules for CVErdict (Exploited or Likely next at knob 50), "CVSS 7 or more" and "EPSS
10% or more":

- **The forward log** (`pipeline/src/receipts.ts`) records, every hour, when each method first
  flagged each window CVE, and later whether that came before CISA's KEV listing. It started on
  2026-11-03 and has no results yet; it never fills in anything from before it started.
- **The backtest** (`pipeline/src/backtest.ts`, `npm run backtest`) re-scores every KEV addition
  of the last 180 days with the evidence of the day before its listing wherever the source dates
  it, and leaves undated evidence out (its "strict" figures) or adds today's value ("with undated
  evidence", usually the higher figure). It is hindsight and labelled as such.

The backtest on 2026-11-03 (178 KEV additions since 2026-05-07; 38 left out because the CVE was
published on or after its listing day, 1 without a published record):

| Published up to 2 years before the listing (120) | Flagged before KEV (strict) | With undated evidence |
|---|--:|--:|
| CVErdict | 42 (35.0%) | 84 (70.0%) |
| CVSS 7 or more | 65 (54.2%) | 108 (90.0%) |
| EPSS 10% or more | 17 (14.2%) | 17 (14.2%) |

For the 19 CVEs published more than 2 years before their listing: CVErdict 15 (17 with undated
evidence), CVSS 7 or more 3 (19), EPSS 10% or more 12. Over the same 180 days, with today's evidence, CVErdict
flags 2.6% of the 68,198 new CVEs, CVSS 7 or more 52.2% and EPSS 10% or more 0.2%.

The strict figures are unflattering for CVErdict, and for a known reason: CISA rewrites its part of
the CVE record when it lists a CVE, so the strict variant cannot use CISA's SSVC exploitation value
or CISA-ADP CVSS for almost any of these CVEs, and a CNA record changed after the listing loses its
CVSS too. CVSS 7 or more catches more of these CVEs before KEV, at twenty times the alert volume.
The forward log is the measurement that settles it.

## Known blind spots

- **Vendor zero-days without artifacts.** Targeted exploitation of edge devices and enterprise
  software is often disclosed with a patch, with no public exploit, no "in the wild" wording in the
  CVE record and no KEV entry for days. These sit in Watch, or even Quiet, until KEV or the vendor
  catches up.
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
and the tier thresholds (knob range, Watch floor) in [`shared/contract.ts`](../shared/contract.ts).
A change to either is a new score model.

1. Open an issue first if the change is large, with the reasoning and the evidence behind it.
2. In the pull request, bump `SCORE_MODEL` (minor version for re-weighting, major for a new family
   or a changed rule) and update the unit tests and this document.
3. Include a **calibration diff**: the output of `npm run calibrate -- --offline --now <same instant>`
   before and after the change (tiers and pass rate at knobs 40–60, KEV recall measured as above,
   the largest batch), plus the 20 CVEs whose tier moved the most, with their chips (compare two
   `npm run pipeline -- --offline --now <same instant>` outputs).
4. Explain what the change gets wrong as well as what it gets right. A weight that only helps
   look-ahead (evidence that appears after exploitation is known) will be declined.

Disagreeing with a single score is just as welcome: use the "Disagree?" button on the CVE page, or
the [issue template](https://github.com/markusweldon/cverdict/issues/new?template=disagree-with-a-score.yml).
