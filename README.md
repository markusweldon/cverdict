<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img alt="CVErdict" src="docs/assets/logo-light.svg" width="480">
</picture>

**Every CVE gets a verdict. Every verdict comes with receipts.**

Open-source CVE triage for the 2026 flood: the few CVEs that matter today, and exactly why.

<sub>Say it "C-V-E-rdict", like "CVE verdict" run together.</sub>

[![ci](https://github.com/markusweldon/cverdict/actions/workflows/ci.yml/badge.svg)](https://github.com/markusweldon/cverdict/actions/workflows/ci.yml)
[![refresh-data](https://github.com/markusweldon/cverdict/actions/workflows/refresh.yml/badge.svg)](https://github.com/markusweldon/cverdict/actions/workflows/refresh.yml)
[![npm: cverdict-mcp](https://img.shields.io/npm/v/cverdict-mcp?label=npm%3A%20cverdict-mcp&color=c6f432&labelColor=111317)](https://www.npmjs.com/package/cverdict-mcp)
[![code: MIT](https://img.shields.io/badge/code-MIT-c6f432?labelColor=111317)](LICENSE)
[![scores: CC0](https://img.shields.io/badge/scores-CC0-c6f432?labelColor=111317)](#license)

[**Live site**](https://cverdict.dev) · [Use it](#use-it) · [How it works](#how-it-works) · [Scoring](#how-scoring-works) · [Receipts](#receipts) · [MCP](#ask-from-an-ai-agent-mcp) · [Open data API](#open-data-api) · [Deploy your own](#deploy-your-own)

</div>

---

CVErdict is open-source CVE triage for the 2026 flood. Every hour it reads every new CVE record,
joins it with CISA KEV, EPSS and the public exploit feeds, and sorts the last 30 days into four
tiers: **Exploited**, **Likely next**, **Watch** and **Quiet**. Each score is a plain sum of
*reason chips* that you can read and click through to the evidence. There is no machine learning,
no LLM-written text, no NVD dependency and no API key. It is a static site plus an open JSON feed,
rebuilt hourly by GitHub Actions, and a read-only MCP server that reads the same feed, so a fork
gives you your own copy.

<br>

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="docs/assets/signal-narrow-dark.svg">
  <source media="(max-width: 600px)" srcset="docs/assets/signal-narrow-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/signal-dark.svg">
  <img alt="The last 30 days, Oct 24 to Nov 23, 2026: 16,337 new CVEs published, 278 worth your time. That is 1.7% of the flood, 1 in 59, Exploited or Likely next at the default evidence bar of 50. By tier: 26 Exploited, 252 Likely next, 2,853 Watch and 13,206 Quiet. Below, the signal waterfall as the site draws it: every CVE of the window in 2-hour slots, one column of small ticks per slot, taller for busier slots. Quiet ticks are grey and Watch ticks amber at the bottom of each column; the lit red and orange ticks on top are the Exploited and Likely next CVEs that cleared the bar. A red ring marks the 1 CVE newly exploited in the last 72 hours, near Nov 20, and the legend reads 1 newly exploited. Patch days stand out as spikes, labelled Microsoft 1,094 on Nov 10, VulnCheck 389 on Nov 13, Oracle 578 on Nov 17 and Linux kernel 246 on Nov 19." src="docs/assets/signal-light.svg" width="100%">
</picture>

**Thousands in, a few hundred out.** The rest is not hidden: every CVE keeps its score, its tier and its reasons.

<br>

<img alt="Demo of the Today page in the dark theme. The noise meter shows 16,337 new CVEs and 278 worth your time at the Balanced evidence bar of 50, about 9 a day, and the waterfall legend shows 1 newly exploited. Choosing Broad lowers the bar to 40: the count rises to 647, about 22 a day, and more ticks light up in the signal waterfall. Choosing Strict raises it to 60: 142, about 5 a day. Choosing Balanced brings it back to 278. Exploited CVEs and those with a Metasploit module or Nuclei template show at every setting." src="docs/assets/demo-dark.gif" width="100%">

<sub>The Today page with the data of Nov 23, 2026 16:47 UTC, recorded from the production build with
<a href="tools/brand/screens.mjs"><code>tools/brand/screens.mjs</code></a>. The evidence bar re-tiers the page live and the URL remembers it.</sub>

## Use it

| Where | How |
|---|---|
| **In the browser** | Open [cverdict.dev](https://cverdict.dev). No account, no cookies. |
| **From an AI agent** | `claude mcp add cverdict -- npx -y cverdict-mcp` ([other clients](mcp/README.md)) |
| **As JSON** | `curl -s https://raw.githubusercontent.com/markusweldon/cverdict/data/v1/meta.json` ([every file](#open-data-api)) |
| **Your own copy** | Fork it and deploy to Vercel or GitHub Pages ([how](#deploy-your-own)) |

## Why

| Number | What it means |
|--:|:--|
| **102.7k** | CVEs published in 2026 through Nov 23: more than all of 2025 (48.2k) twice over[^ours] |
| **4,302 → 17,050** | CVEs per month, January → October 2026[^ours] |
| **16,337** | new CVEs in the last 30 days. **278** of them (1 in 59) are Exploited or Likely next[^ours] |
| **34** | CVEs added to [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) in the last 30 days: one KEV addition for every ~480 new CVEs[^ours] |
| **1,094** | Microsoft CVE records on Patch Tuesday, Nov 10. **1** exploited ([CVE-2026-124194](https://www.cve.org/CVERecord?id=CVE-2026-124194)), **6** Likely next[^ours] |
| **Apr 15** | NIST's NVD [stopped enriching most CVEs](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/): only KEV-listed, federal and critical software is still analysed |
| **15 → 274** | CVE records crediting AI tools, October 2025 → October 2026[^ours] |

> “…creating larger haystacks, but it isn't finding more needles.”
>
> Satnam Narang, Tenable, on AI-assisted vulnerability discovery ([iTWire](https://itwire.com/guest-articles/guest-opinion/tenable-patch-tuesday-commentary-september))

The needles are still there. CVErdict shows you the few that matter today, and exactly why.

[^ours]: Our counts from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5), CISA KEV and
    EPSS data, from the run of Nov 23, 2026 16:47 UTC (`meta.json`, `stats.json` and `batches.json`
    on the data branch). CVE totals count records in PUBLISHED state by `datePublished`, as the
    site's charts do.

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/how-it-works-dark.svg">
  <img alt="How CVErdict works, top to bottom. Public sources: CVE records from CVE List V5 (430,789 records) and CISA Vulnrichment (225,948), with SSVC and CVSS from CISA and nothing from NVD; confirmed exploitation from CISA KEV (1,790), ENISA EU KEV (82), the CIRCL catalog (30) and SiberKapan (information only); exploits and odds from Metasploit (7,274), Nuclei templates (4,745), Exploit-DB (47,182), PoC-in-GitHub (12,020) and EPSS (411,399); package versions from OSV.dev (47,415), for Check Deps only and never part of a score. They feed the pipeline, a GitHub Actions run every hour at minute 17 that never stops for one failing feed, in five steps: 01 Ingest (fetch, cache, keep the last good copy), 02 Score (reason chips, a plain sum from 15), 03 Tier (four tiers at the evidence bar of 50), 04 Emit (JSON, 256 CVE shards, Atom, iCal) and 05 Validate (every file checked, or nothing ships). The output goes to the data branch, one orphan commit replaced every run, holding v1/meta.json, signal.json, index.json, cve/00 to ff.json, receipts.json, packages.json, the Atom feeds and kev-due.ics. Four readers use that branch: cverdict.dev, a static site on Vercel that rewrites /data/* to the branch so it needs no redeploy; the Atom and iCalendar feeds; the open JSON API on raw.githubusercontent.com with no key and CC0 scores; and the read-only MCP server, npx -y cverdict-mcp. Record counts are from the run of Nov 23, 2026 16:47 UTC." src="docs/assets/how-it-works-light.svg" width="100%">
</picture>

**One writer, many readers.** The hourly run is the only thing that writes. The site, the feeds, the API and the MCP server all read the same files, so they always agree.

If a source is down, the last good copy is used and marked stale on the site; one failing feed
never stops a run. With no copy at all, that source's evidence is shown as unknown, not as absent.
The run writes the whole tree to a temporary folder, validates every file and only then swaps it
in, so a bad run publishes nothing.

<details>
<summary><b>Where each part lives in the repository</b></summary>

<br>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
  <img alt="CVErdict architecture by folder. At the top, .github/workflows/refresh.yml runs on cron at minute 17 every hour, or from an external timer, with four jobs: Build data, Publish, Deploy Pages (optional) and Watchdog. Three columns below. pipeline/src writes: sources/*.ts has one loader per feed (cvelist, kev, catalogs, epss, metasploit, nuclei, exploitdb, poc, osv); ingest.ts tries the primary, then the fallback, then the cache; normalize.ts turns untrusted CVE JSON 5 into plain, checked records; score.ts applies chips and points, strongest per family; woke.ts and receipts.ts track old CVEs that woke up, the forward log and the backtest; batches.ts, stats.ts and packages.ts build patch days, counts and OSV package ranges; emit/ holds json.ts, atom.ts and ics.ts; validate.ts and run.ts check every file and swap the tree in atomically. shared/ is the contract both sides import: contract.ts (every file format and tierFor), model.ts (every chip and its points, score model v0.4.0), verdict.ts (the one-line verdict), shard.ts (FNV-1a of the CVE ID picks one of 256 detail files), packages.ts and versions.ts (version ranges for eight ecosystems) and brand.ts. The readers only read: site/src (Preact and Vite), site/src/check (SBOM and lockfile parsers that run in the browser), api/share.ts (link previews for chat and social bots only), mcp/src (the npm package cverdict-mcp) and vercel.json (rewrites /data/* and /feeds/* to the data branch). At the bottom, scripts/publish-data-branch.sh writes one parentless commit per run to the data branch, which the readers fetch. scripts/backtest.ts and calibrate.ts reproduce the numbers, and ci.yml runs typecheck, tests, both builds and an MCP smoke test." src="docs/assets/architecture-light.svg" width="100%">
</picture>

</details>

## How scoring works

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="docs/assets/scoring-narrow-dark.svg">
  <source media="(max-width: 600px)" srcset="docs/assets/scoring-narrow-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/scoring-dark.svg">
  <img alt="How a CVErdict score adds up. The score is a base of 15 plus five families: Exploits (exploit code, templates and EPSS) from minus 14 to plus 34, Severity (CVSS from the CNA or CISA) from minus 13 to plus 13, CISA SSVC (automatable, technical impact) from minus 8 to plus 14, KEV history (vendor or product exploited before) from minus 6 to plus 10, and Noise (tutorial code, disputed, WordPress) from minus 20 to 0. Confirmed exploitation adds 75 and floors the score at 90: CISA KEV, EU KEV, CIRCL, SSVC active or the vendor. On the 0 to 100 scale, at the default evidence bar of 50: Quiet below 25, Watch from 25 to 50, Likely next from 50, and Exploited from 90. The bar can be moved from 35 to 65 on the site and from 30 to 80 in the API and MCP server. Worked example, CVE-2026-119958, a Windows LDAP remote code execution vulnerability: base 15, plus 20 for one PoC repo (vetted), plus 13 for Critical 9.8 network, plus 8 for CISA SSVC total technical impact, plus 6 for automatable, plus 8 for Vendor in KEV (Microsoft, 391 times) equals 70, Likely next. Its patch-day membership and its EPSS of 1.6% on day 12 count 0 points. The tier rules: Exploited means patch now, on any confirmed exploitation chip; Likely next means patch within days, for a score at or above the bar, or a Metasploit module or Nuclei template, which always passes; Watch means keep an eye on it, for a score from 25 up to the bar; Quiet means no evidence yet, below 25, and Quiet is not safe." src="docs/assets/scoring-light.svg" width="100%">
</picture>

**Evidence over severity.** Half of all new CVEs are High or Critical, so CVSS is a small modifier here. What moves a score is evidence that someone can, or does, exploit the bug.

```text
score = 15 + X (exploit artifacts or the fast lane, strongest one) + SEV (CVSS) + SSVC (CISA) + PRIOR (KEV history) + NOISE
```

Any confirmed exploitation adds 75 and floors the score at 90. Within a family only the strongest
chip counts, so three PoCs and a Metasploit module are not four times the evidence. Points are
roughly 20 · log10 of how much each signal raised the odds of a later KEV listing, shrunk for
look-ahead bias: +20 points ≈ 10× the odds. For the first 14 days the feeds have not caught up,
so EPSS is ignored and "no exploit yet" costs 3 points instead of 14. On an internet-facing edge
device (VPN, firewall, gateway and the like, a [curated list](docs/SCORING.md#internet-facing-edge-devices))
it costs nothing, since those are often attacked before any exploit is public. In the same 14
days, a network bug that CISA calls automatable with total impact (or CVSS 9 or more before CISA
has assessed it), on an edge device or in a product already in KEV, gets the
[fast lane](docs/SCORING.md#fast-lane), +12, and is Likely next from day 0: attack tools now build
exploits for such bugs in hours. A feed that could not be loaded counts as unknown, never as "no
exploit".

Every CVE published in the last 30 days, every CVE in KEV (CISA's, or listed as exploited by ENISA
EU KEV or CIRCL) and every older CVE that woke up in the last 30 days gets a score from 0 to 100
and a tier:

| Tier | What it means | What puts a CVE here |
|---|---|---|
| **Exploited** | Patch now. | Confirmed exploitation: CISA KEV, ENISA's EU KEV, CIRCL's catalog, CISA's SSVC assessment says *active*, or the vendor says so |
| **Likely next** | Patch within days. | A Metasploit module or Nuclei template (always at least Likely), or a score at or above the evidence bar |
| **Watch** | Keep an eye on it. | Score from 25 up to the evidence bar |
| **Quiet** | No evidence yet. **Quiet ≠ safe.** | Score below 25 |

The **evidence bar** is the minimum score (out of 100) to flag a CVE as likely exploited next
("Likely next"). It defaults to 50 and the site's dial runs from 35 to 65 (the API and MCP server
accept 30 to 80, parameter `knob`). Lower it to see more, raise it for fewer CVEs with more
evidence behind each; the page re-tiers live and the URL remembers your setting.
[SCORING.md](docs/SCORING.md#tiers-and-the-evidence-bar) explains the range.

Every score is explained by reason chips, each linked to its source. These are the chips of
[CVE-2026-88771](https://www.cve.org/CVERecord?id=CVE-2026-88771), a NetScaler ADC remote code
execution bug, in the run of Nov 23:

```text
CISA KEV · added Sep 27 · due Sep 30
Listed in ENISA EU KEV
Listed by CIRCL (CC0) as exploited · added Sep 28
CISA SSVC: exploitation active · Sep 27
Metasploit: exploit/freebsd/http/citrix_netscaler_cve_2026_88771 (normal)
EPSS 81.9% · 99th pct
12 PoC repos (12 vetted), unverified, may be malware
Critical 9.5 · network (v4.0)
CISA SSVC: total technical impact
CISA SSVC: automatable
Product in KEV (×5): Citrix NetScaler
KEV due Sep 30 · 54 days ago
CISA asks for forensic triage (BOD 26-04)
Internet-facing edge device: Citrix NetScaler ADC and Gateway (load balancer, gateway)
```

Other CVEs carry chips such as `Vendor CVSS: working exploit code exists (E:F)` (+24: weaponized,
not yet exploited), `Fast lane: network, automatable, total impact, product in KEV` (+12 in the
first 14 days), context worth 0 points such as `Part of Microsoft patch day · Nov 10 (1,094)`
or `AI-credited: “Claude Security”` or `Internet-facing edge device: F5 BIG-IP (load balancer, gateway)`, and unknowns
such as `Not settled: 1 PoC repo too new to vet (day 9 of 14)`.

Does it find exploited CVEs before KEV does? Hide the answer key (each CVE's own KEV listing, CISA's
SSVC *active* and any EPSS score from the listing day on) and re-score the 137 recent CVEs CISA
added to KEV from May 24 to Nov 20, 2026: **99 (72%)** still land in Exploited or Likely next,
while CVErdict flagged only **2.3%** of the 76,097 new CVEs of that period. Treat that as an upper
bound, since it counts evidence that has no date. With only evidence dated before each listing it is
59 (43%). From the backtest of Nov 20, 2026 (score model v0.3.0); `npm run backtest` reproduces it.

The full methodology, every chip with its points, the calibration and the known blind spots are in
[docs/SCORING.md](docs/SCORING.md).

## Receipts

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/receipts-dark.svg">
  <img alt="Receipts, a hindsight backtest: flagged before CISA listed it in KEV. 137 CVEs CISA added to KEV from May 24 to Nov 20, 2026, scored with only the evidence dated before each listing, next to two common rules. KEV CVEs caught before the listing, of 137: CVErdict 59 (43%), CVSS 7 or more 80 (58%), EPSS 10% or more 18 (13%). Alert volume, the share of all 76,097 CVEs scored: CVErdict 1,777 (2.3%), CVSS 7 or more 39,982 (52.5%), EPSS 10% or more 133 (0.17%). Below, the live record since Nov 3, 2026, 547 runs: of 18 KEV listings, CVErdict flagged 8 before CISA, a median of 4.5 days early; CVSS 7 flagged 14 and EPSS 10% flagged 0. From receipts.json: backtest of Nov 20, 2026 (score model v0.3.0), live record to Nov 23, 2026 16:47 UTC." src="docs/assets/receipts-light.svg" width="100%">
</picture>

**In the hindsight backtest, CVErdict catches three quarters of what CVSS 7 catches, with less than a twentieth of the alerts:** 59 of 137 against 80, while flagging 2.3% of new CVEs against 52.5%. The live record is still small: of 18 KEV listings, CVErdict flagged 8 before CISA listed them, against 14 for CVSS 7 (13 earlier and 1 on the listing day itself).

The [Receipts page](https://cverdict.dev/receipts) holds the stricter tests. A live record notes,
to the minute, when each method first flags a CVE and whether that came before CISA listed it; the
page shows how many listings it has judged so far. A backtest, marked as hindsight, uses only
evidence dated before each listing. On the inputs of Nov 20, 2026 (score model v0.3.0), for the
137 recent CVEs CISA added to KEV in the previous 180 days, it gave: CVErdict 59 flagged before the
listing, "CVSS 7 or more" 80, "EPSS 10% or more" 18. CVSS 7 or more catches more, but flags 52.5% of
all new CVEs against CVErdict's 2.3%. The Receipts page always shows the latest run.
`npm run backtest` reproduces it.

## On the site

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/surfaces-dark.svg">
  <img alt="Twelve ways in, one verdict. No account, no tracking, no cookies, and keyboard first: j and k to move, slash to search, Ctrl K for everything. Today, at /: the noise meter, the signal waterfall, the evidence bar and the signal feed. CVE pages, at /cve/ID: the verdict, the score chip by chip, what we could not see and Copy as ticket. KEV Clock, at /kev: every KEV due date counting down, with ransomware and forensic flags. Woke Up, at /woke: old CVEs that gained exploitation evidence in the last 30 days. Receipts, at /receipts: flagged before KEV, next to CVSS 7 and EPSS 10%, every hit and miss. Check Deps, at /check: drop an SBOM or lockfile, read in your browser and never uploaded. Explore, at /explore: every CVE of the window, searchable and filterable by day. Batches, at /batches: patch days and bulk releases, and the few CVEs in each that matter. The Surge, at /surge: monthly CVE volume since 1999, KEV additions and AI-credited CVEs. Method, at /method: every chip, its points and the known blind spots. MCP, at /mcp: add the read-only MCP server to an AI agent in one command. Feeds and API, at /feeds: Atom and iCalendar feeds and the open JSON files." src="docs/assets/surfaces-light.svg" width="100%">
</picture>

<table>
<tr>
<td width="50%" valign="top"><a href="https://cverdict.dev/cve/CVE-2026-119958"><img alt="The page of CVE-2026-119958, a Windows LDAP remote code execution bug in Microsoft Windows 10 Version 1607, part of the Nov 10 patch day. Tier Likely next, with the verdict: public proof of concept (1 vetted repo). Buttons for Copy as ticket, Copy link, JSON and cve.org. The evidence by family: exploit artifacts plus 20 for 1 PoC repo, severity plus 13 for Critical 9.8 network, CISA SSVC plus 14. The score dial reads 70 out of 100, and the arithmetic adds base 15, plus 20, 13, 8, 6 and 8." src="docs/assets/screens/cve.webp"></a><br><sub><b>CVE page.</b> The verdict, every chip and its points, and the sum.</sub></td>
<td width="50%" valign="top"><a href="https://cverdict.dev/check"><img alt="Check Deps results for a sample package-lock.json with 7 packages: 5 tracked CVEs affect 4 of them, 4 Exploited and 1 Likely next. The Exploited group lists CVE-2023-5217 and CVE-2023-4863 in electron 22.3.0, CVE-2023-22894 in @strapi/strapi 4.5.0 and CVE-2025-54313 in eslint-config-prettier 8.10.1, each with its GitHub advisory, the affected ranges and the fixed version." src="docs/assets/screens/check.webp"></a><br><sub><b>Check Deps.</b> Your SBOM or lockfile, matched in the browser. Nothing is uploaded.</sub></td>
</tr>
<tr>
<td valign="top"><a href="https://cverdict.dev/receipts"><img alt="The Receipts page: the live record since Nov 3, 2026. CISA added 18 CVEs CVErdict had already seen to KEV; CVErdict flagged 8 of them before CISA listed them, a median of 4.5 days earlier. A table compares CVErdict, CVSS 7 or more and EPSS 10% or more on flagged before KEV, same day, median lead and alert volume." src="docs/assets/screens/receipts.webp"></a><br><sub><b>Receipts.</b> Every hit and every miss, against CVSS 7 and EPSS 10%.</sub></td>
<td valign="top"><a href="https://cverdict.dev/woke"><img alt="The Woke Up page: CVEs published more than 30 days ago that gained exploitation evidence in the last 30 days, 252 of them, filterable by CISA KEV, EU KEV or CIRCL, Exploit-DB, Metasploit, Nuclei, PoC repo and EPSS jump. The first entries are CVE-2026-112947 in Vite and CVE-2026-35413 in Directus, each with a first Nuclei template seen on Nov 23." src="docs/assets/screens/woke.webp"></a><br><sub><b>Woke Up.</b> Old CVEs with new exploitation evidence, each with its dated proof.</sub></td>
</tr>
<tr>
<td valign="top"><a href="https://cverdict.dev/kev"><img alt="The KEV Clock page. The next deadline counts down in large red digits: CVE-2025-42884, SAP NetWeaver, due Nov 23. Beside it: 8 due within 72 hours, 7 overdue in the last 7 days, 34 added in 30 days, 1 of them with known ransomware use. Below, the list of CVEs due within 72 hours with the date added, the due date and the score." src="docs/assets/screens/kev.webp"></a><br><sub><b>KEV Clock.</b> Federal due dates, counting down.</sub></td>
<td valign="top"><a href="https://cverdict.dev/surge"><img alt="The Surge page. 2026 so far: 102,712 CVEs, plus 145% on the same days of 2025. Busiest month ever: 17,050 in October 2026. 25% of all CVEs since 1999 were published in 2026 alone. 306 added to KEV this year, about 0.3% of the volume. Below, the chart of CVEs per month since 1999 climbs steeply through 2025 and 2026, with KEV additions and AI-credited CVEs near the floor." src="docs/assets/screens/surge.webp"></a><br><sub><b>The Surge.</b> Monthly volume since 1999, KEV additions and AI credits.</sub></td>
</tr>
</table>

<sub>Screenshots of the production build with the data of Nov 23, 2026 16:47 UTC, dark theme. The site also has a light theme.</sub>

What the card leaves out:

- **Today**: CVEs newly exploited in the last 72 hours pulse on the waterfall, and the legend
  opens a list of them. Click a waterfall column to see that day's CVEs in Explore, or a spike
  label to open its patch-day batch. The feed has filters and a vendor watchlist.
- **CVE pages**: a link shared in Slack, X, LinkedIn, Mastodon, Discord or a messenger shows the
  verdict and score in its preview.
- **Woke Up** watches CVEs that left the window. It counts a CISA KEV, EU KEV or CIRCL listing,
  an EPSS jump or a first public exploit: an Exploit-DB entry, Metasploit module, Nuclei template,
  or a GitHub PoC repo at least 3 days old or with 2 stars (the code is not checked).
- **Check Deps** reads CycloneDX, SPDX, package URL lists and npm, yarn, pnpm, pip, Poetry, uv,
  Pipenv, Go, Cargo, Bundler, Composer, NuGet and Gradle lockfiles. It knows only the tracked CVEs,
  so it is not a full audit.
- **Keys**: `j`/`k`, `/`, `Ctrl K`, `?`.

## Data sources

Only free, public data. Nothing from NVD.

| Source | What we use | Checked | License |
|---|---|---|---|
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Every CVE record: CNA data, CVSS, exploit maturity, credits | hourly | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) (ADP container in each record) | SSVC decision points; CVSS when the CNA gave none | hourly | CC0-1.0 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed exploitation, due dates, ransomware use, vendor history | hourly | CC0-1.0 |
| [ENISA EU KEV](https://euvd.enisa.europa.eu/) (EUVD) | Exploitation reported by ENISA or a national CSIRT of the EU CSIRTs Network, and the date it was listed | every 6 h (published daily) | ENISA material, reproduced with acknowledgement of the source |
| [CIRCL known exploited catalog](https://vulnerability.circl.lu/known-exploited-vulnerabilities-catalog/?catalog_uuid=1a89b78e-f703-45f3-bb86-59eb712668bd) | Exploitation CIRCL (Computer Incident Response Center Luxembourg, the CERT for Luxembourg's private sector) confirms or suspects | every 12 h | CC0-1.0 |
| [SiberKapan honeypot catalog](https://siberkapan.org/kev-catalog) (through CIRCL Vulnerability-Lookup) | Exploitation attempts seen by honeypot and web server sensors in Turkey, shown for information only | every 12 h | CC-BY-4.0 |
| [EPSS](https://www.first.org/epss/) (FIRST) | Probability of exploitation activity in the next 30 days | hourly (published daily) | Free use with attribution |
| [Metasploit Framework](https://github.com/rapid7/metasploit-framework) | Modules that reference a CVE | hourly | BSD-3-Clause |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) | Templates that reference a CVE, and when the first one for each CVE landed (from the repository's history) | hourly | MIT |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) | Entries that reference a CVE (IDs and links only) | every 6 h | GPL-2.0 |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Public proof-of-concept repositories per CVE | hourly | CC0-1.0 |
| [OSV.dev](https://osv.dev/) (GitHub Advisory Database, PyPA, Go, RustSec and Drupal advisories) | Package versions affected by the tracked CVEs, for the Check Deps page only; never part of a score | hourly (full copy weekly) | CC-BY-4.0 (GitHub, PyPA, Go), CC0-1.0 (RustSec), MIT (Drupal) |

What happens when a source is down is under [How it works](#how-it-works). Details and required
notices: [ATTRIBUTIONS.md](ATTRIBUTIONS.md).

## Open data API

Everything the site shows is plain JSON on the `data` branch, refreshed hourly. No key, no rate
limit beyond GitHub's, CC0 for our scores.

```sh
BASE=https://raw.githubusercontent.com/markusweldon/cverdict/data/v1

# Headline numbers for the window
curl -s $BASE/meta.json | jq '{generated_at, published: .counts.window_published, passed: .counts.window_passed}'

# Every CVE exploited in the last 30 days: id, score, vendor, product
curl -s $BASE/signal.json | jq -r '
  .cols as $c | .rows[] | [$c, .] | transpose | map({(.[0]): .[1]}) | add
  | select(.tier == "exploited") | [.id, .s, .v, .p] | @tsv'

# The full reasoning for one CVE (details are sharded by an FNV-1a hash of the ID)
id=CVE-2026-96951
shard=$(node -p 'let h=0x811c9dc5;for(const c of process.argv[1].toUpperCase())h=Math.imul(h^c.charCodeAt(0),0x01000193);((h>>>0)%256).toString(16).padStart(2,"0")' $id)
curl -s $BASE/cve/$shard.json | jq -r --arg id $id '.items[$id].reasons[] | "\(.points)\t\(.label)"'
```

Feeds: [Atom: Exploited + Likely next](https://raw.githubusercontent.com/markusweldon/cverdict/data/feeds/signal.xml) ·
[Atom: KEV additions](https://raw.githubusercontent.com/markusweldon/cverdict/data/feeds/kev.xml) ·
[Atom: old CVEs that woke up](https://raw.githubusercontent.com/markusweldon/cverdict/data/feeds/woke.xml) ·
[iCalendar: KEV due dates](https://raw.githubusercontent.com/markusweldon/cverdict/data/feeds/kev-due.ics)
(also served from the site under `/feeds/`). `woke.json` lists the old CVEs that woke up,
`receipts.json` holds the Receipts figures with every hit and miss, and `packages.json` the package
versions the tracked CVEs affect, which the Check Deps page compares with your file.

Every file, every field, sharding and the versioning policy: [docs/DATA.md](docs/DATA.md).

## Ask from an AI agent (MCP)

CVErdict also runs as a read-only [MCP](https://modelcontextprotocol.io) server, so an AI agent can
ask for verdicts and get the same score, chips and links as the site, with the time of the run and
the files behind every answer. No key, no account. It runs on your machine and reads the `data`
branch on GitHub directly, so it does not depend on the site. It is the npm package
[`cverdict-mcp`](https://www.npmjs.com/package/cverdict-mcp) (Node 22.12 or later):

```sh
claude mcp add cverdict -- npx -y cverdict-mcp      # Claude Code; other clients: mcp/README.md
```

To run a given commit or work on the server, run it from a clone instead:

```sh
git clone --single-branch https://github.com/markusweldon/cverdict.git
cd cverdict && npm ci
claude mcp add cverdict -- npm --prefix "$PWD" run -s mcp
```

Tools: `get_verdict` (1 to 15 CVE IDs), `list_signal`, `kev_due`, `woke_up`, `receipts` and
`search_cves`. Setup for other clients, options and limits: [mcp/README.md](mcp/README.md); what
each answer contains: [docs/DATA.md](docs/DATA.md#mcp-server); copyable commands on the site:
[MCP Server](https://cverdict.dev/mcp).

## Deploy your own

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/markusweldon/cverdict)

**Vercel, zero config.** Import the repository and deploy. The site is static; `/data/*` and
the feed files under `/feeds/` are rewritten to the `data` branch on raw.githubusercontent.com, so
fresh data arrives every hour without a redeploy. One small function answers link-preview bots
only, so shared CVE links show their verdict; people never reach it
([Link previews](docs/DEPLOY.md#link-previews)). A fresh clone reads this repository's data until
you point it at your own: set `repo` in `shared/brand.ts` and change the `/data/` and `/feeds/`
rewrites in `vercel.json` (see [Forking and renaming](docs/DEPLOY.md#forking-and-renaming)). Until
then it needs no workflow runs of its own.

**GitHub Pages.** The repository must be public, because the refresh workflow reads the `data`
branch anonymously.

1. Fork the repository and enable Actions on the fork.
2. Settings → Pages → Source: **GitHub Actions**.
3. Settings → Secrets and variables → Actions → **Variables**: add `REFRESH_SCHEDULE` = `on`.
   Copies skip the hourly schedule without it.
4. Actions → **refresh-data** → Run workflow. From then on it publishes the data and redeploys
   the site every hour.

Pages has no functions, so a shared CVE link shows the site card, not its verdict, and CVE pages
are served with status 404 (they still work in a browser). For links you want to share, use Vercel.

GitHub often runs the hourly schedule late. To refresh every hour, start the workflow from a free
external timer: [Reliable hourly refresh](docs/DEPLOY.md#reliable-hourly-refresh).

Renaming, custom domains, the optional `SITE_URL` variable and troubleshooting: [docs/DEPLOY.md](docs/DEPLOY.md).
Hosting costs nothing on either platform's free tier.

## Local development

Requires Node 22.12+, git and about 1 GB of disk.

```sh
npm ci
npm run mock                   # instant: a deterministic mock dataset in site/public/data
npm run pipeline               # or the real data: the first run clones cvelistV5 (~400 MB), a few minutes
npm run dev                    # http://localhost:5173
```

Both write to `site/public/data/`, which the dev server serves. Useful pipeline flags:
`--offline` (replay the cache), `--now 2026-10-26T19:30:00Z` (freeze time),
`--cvelist-dir` / `--poc-dir` / `--nuclei-dir` (reuse existing clones). `npm run calibrate` takes the same flags
and prints the calibration tables. `npm test` and `npm run typecheck` run the main checks. CI also
builds the site and the MCP server, smoke-tests the server and tests the data-branch publisher (see
`.github/workflows/ci.yml`).
More in [CONTRIBUTING.md](CONTRIBUTING.md).

The README images in `docs/assets/` are generated from code and data: `npm run brand` rebuilds the
logo and the diagrams from the live data branch (or `-- --data <dir>`), `node tools/brand/render.mjs`
renders the social preview PNG and `node tools/brand/screens.mjs` retakes the screenshots and the
demo GIF from a running build. See [tools/brand/README.md](tools/brand/README.md).

## Roadmap

**v1.1**

- **CNA noise panel**: each CNA's volume over the years and how much of it reached KEV (The Surge
  already ranks the CNAs of the last 30 days).
- **EPSS sparklines** on CVE pages and rows.
- **Open Graph images** per CVE. Shared CVE links already carry the verdict, score, KEV and exploit status in
  their preview text, with an image per tier; an image with each CVE's own score may follow.

**v2**

- **Browser extension** that puts the verdict next to any CVE ID on the web.
- **MSRC exploitability index** as a chip for Microsoft CVEs.

## Honest limitations

- **Not in KEV ≠ not exploited.** KEV lists exploitation CISA can confirm, often days or weeks
  late, and it leans toward products US agencies run.
- **Quiet ≠ safe.** Quiet means no public evidence *yet*. Targeted zero-days often leave no
  public artifact until well after the damage.
- **Exposure is yours.** We do not know what you run, where it is reachable or what it protects.
  A Watch CVE on your internet-facing VPN can matter more than an Exploited one in software you
  do not have.
- **The weights are v0 and retrospective.** They were fitted on history with look-ahead bias.
  Treat the score as an ordering, not a probability.
- **Upstream errors flow through.** Descriptions, product names and CVSS vectors are as the CNA
  published them.
- **PoC links are unverified third-party code** and may be malware. Never run one outside a lab.
- **Check Deps is not a scanner.** It knows only the tracked CVEs that an advisory ties to a package
  version, in eight ecosystems. "Affected" means the version is inside the advisory's range, not
  that your code reaches the vulnerable part.

## Contributing

Bug reports, data-source proposals and score disputes are all welcome; each has an
[issue template](https://github.com/markusweldon/cverdict/issues/new/choose). Every CVE page has a
"Disagree?" button that opens a prefilled one. To change the weights, open a pull request with a
calibration diff (`npm run calibrate` before and after): see [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues go through [private reporting](SECURITY.md).

## License

- **Code**: [MIT](LICENSE).
- **Data we create** (scores, tiers, reason chips, batches, stats): [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
- **Upstream data** stays under its own terms. CVE records are © The MITRE Corporation and used under
  the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse); the rest is listed in
  [ATTRIBUTIONS.md](ATTRIBUTIONS.md).

## Acknowledgements

CVErdict stands entirely on public work: the [CVE Program](https://www.cve.org/) and its CNAs;
CISA for [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
[Vulnrichment](https://github.com/cisagov/vulnrichment); ENISA and the EU CSIRTs Network for the
[EU KEV](https://euvd.enisa.europa.eu/); CIRCL for [Vulnerability-Lookup](https://vulnerability.circl.lu/)
and its known exploited catalog; [SiberKapan](https://siberkapan.org/kev-catalog); the [FIRST EPSS SIG](https://www.first.org/epss/)
and Empirical Security; CERT/CC for [SSVC](https://github.com/CERTCC/SSVC); Rapid7 and the
[Metasploit](https://github.com/rapid7/metasploit-framework) community;
[ProjectDiscovery](https://github.com/projectdiscovery/nuclei-templates); OffSec's
[Exploit-DB](https://www.exploit-db.com/); [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub);
[OSV.dev](https://osv.dev/) and the GitHub Advisory Database, PyPA, Go, RustSec and Drupal advisory
databases it collects; and Vercel for the [Geist](https://vercel.com/font) typefaces. None of them endorse this project.
