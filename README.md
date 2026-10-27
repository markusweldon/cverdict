<div align="center">

# CVErdict

### Every CVE gets a verdict. Every verdict comes with receipts.

[**Live site**](https://cverdict.vercel.app) · [Methodology](docs/SCORING.md) · [Open data API](docs/DATA.md) · [Deploy your own](#deploy-your-own)

[![ci](https://github.com/markusweldon/cverdict/actions/workflows/ci.yml/badge.svg)](https://github.com/markusweldon/cverdict/actions/workflows/ci.yml)
[![refresh-data](https://github.com/markusweldon/cverdict/actions/workflows/refresh.yml/badge.svg)](https://github.com/markusweldon/cverdict/actions/workflows/refresh.yml)
[![code: MIT](https://img.shields.io/badge/code-MIT-blue)](LICENSE)
[![scores: CC0](https://img.shields.io/badge/scores-CC0-brightgreen)](#license)

</div>

CVErdict is open-source CVE triage for the 2026 flood. Every hour it reads every new CVE record,
joins it with CISA KEV, EPSS and the public exploit feeds, and sorts the last 30 days into four
tiers: **Exploited**, **Likely next**, **Watch** and **Quiet**. Each score is a plain sum of
*reason chips* that you can read and click through to the evidence. There is no machine learning,
no LLM-written text, no NVD dependency and no API key. It is a static site plus an open JSON feed,
rebuilt hourly by GitHub Actions, so a fork gives you your own copy.

## The problem in numbers

| | |
|--:|:--|
| **88.8k** | CVEs published in 2026 through Oct 25: **+78%** on all of 2025[^ours] |
| **4,302 → 14,934** | CVEs per month, January → September 2026[^ours] |
| **16,009** | new CVEs in the last 30 days[^ours] |
| **26** | CVEs added to [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) in October: one KEV addition for every ~540 new CVEs[^ours] |
| **1,407** | Microsoft CVE records on Patch Tuesday, Oct 13. **1** exploited ([CVE-2026-96951](https://www.cve.org/CVERecord?id=CVE-2026-96951)), **2** with a public PoC[^ours] |
| **Apr 15** | NIST's NVD [stopped enriching most CVEs](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/): only KEV-listed, federal and critical software is still analysed |
| **23%** | of new CVEs have an EPSS score on day 0[^ours] |
| **15 → 216** | CVE records crediting AI tools, October 2025 → October 2026 to date[^ours] |

> “AI is creating larger haystacks, but it isn't finding more needles.”
> — Satnam Narang, Tenable ([iTWire](https://itwire.com/guest-articles/guest-opinion/tenable-patch-tuesday-commentary-september))

The needles are still there. CVErdict shows you the few that matter today, and exactly why.

[^ours]: Our counts from [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5), CISA KEV and
    EPSS data as of Oct 26, 2026. CVE totals count records by `datePublished`, including records
    rejected since; the site's charts count only records still in PUBLISHED state, so they run
    about 2% lower.

## What it does

Every CVE published in the last 30 days, plus every CVE in KEV, gets a score from 0 to 100 and a tier:

| Tier | What it means | What puts a CVE here |
|---|---|---|
| **Exploited** | Patch now. | Confirmed exploitation: CISA KEV, CISA's SSVC assessment says *active*, or the vendor says so |
| **Likely next** | Patch within days. | A Metasploit module or Nuclei template (always at least Likely), or a score at or above the knob |
| **Watch** | Keep an eye on it. | Score from 25 up to the knob |
| **Quiet** | No evidence yet. **Quiet ≠ safe.** | Score below 25 |

The **knob** (default 50, range 30–80) sets how much evidence "Likely next" needs. Turn it down to
see more, up to see less; the page re-tiers live and the URL remembers your setting.

Every score is explained by reason chips, each linked to its source:

```text
CISA KEV · added Oct 21 · due Oct 24
Metasploit: exploit/linux/http/foo (excellent)
EPSS 14.2% · 99th pct
Critical 9.8 · network
3 PoC repos (2 vetted) — unverified, may be malware
Product in KEV (×4)
AI-credited: “Claude Opus 5”
Part of Microsoft · Oct 13 (1,407)
```

On the site:

- **Today**: the noise meter (every CVE of the last 30 days → the few worth your time), a signal
  waterfall of the whole window hour by hour, the knob, the signal feed with filters and a vendor
  watchlist, patch-day batch cards, the KEV due-date clock and what changed since the last run.
- **CVE pages**: a one-line verdict, the score arithmetic chip by chip, what we could *not* see,
  an evidence timeline, the facts (CVSS vector, SSVC, EPSS, KEV, affected products) and
  "Copy as ticket".
- **KEV clock**, **Batches**, **Explore** (every window CVE, searchable), **The surge** (monthly
  volume since 1999), **Method** and **Feeds**.
- Keyboard first: `j`/`k`, `/`, `⌘K`, `?`. No account, no tracking, no cookies.

![Today: the noise meter, the signal waterfall and the knob](docs/screenshots/home.png)

![A CVE page: the verdict, the score arithmetic and its reason chips](docs/screenshots/cve.png)

## How scoring works

```text
score = 15 + X (exploit artifacts, strongest one) + SEV (CVSS) + SSVC (CISA) + PRIOR (KEV history) + NOISE
```

Any confirmed exploitation adds 75 and floors the score at 90. Within a family only the strongest
chip counts, so three PoCs and a Metasploit module are not four times the evidence. Points are
roughly 20 · log10 of how much each signal raised the odds of a later KEV listing, shrunk for
look-ahead bias: +20 points ≈ 10× the odds. EPSS and "no exploit yet" are ignored for the first
14 days, because the feeds have not caught up.

A real example:

```text
CVE-2026-105016 · Microsoft QUIC Remote Code Execution Vulnerability · day 13

   15  base
  +13  Critical 9.8 · network (v3.1)
   +8  CISA SSVC: total technical impact
   +6  CISA SSVC: automatable
   +8  Vendor in KEV (×390): Microsoft
    0  Too new: day 13 of 14 — exploit feeds lag
  ───
   50  Likely next at the default knob
```

The full methodology, every chip with its points, the calibration and the known blind spots are in
[docs/SCORING.md](docs/SCORING.md).

## Data sources

Only free, public data. Nothing from NVD.

| Source | What we use | Checked | License |
|---|---|---|---|
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Every CVE record: CNA data, CVSS, exploit maturity, credits | hourly | [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse) |
| [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) (ADP container in each record) | SSVC decision points; CVSS when the CNA gave none | hourly | CC0-1.0 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed exploitation, due dates, ransomware use, vendor history | hourly | CC0-1.0 |
| [EPSS](https://www.first.org/epss/) (FIRST) | Probability of exploitation activity in the next 30 days | hourly (published daily) | Free use with attribution |
| [Metasploit Framework](https://github.com/rapid7/metasploit-framework) | Modules that reference a CVE | hourly | BSD-3-Clause |
| [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) | Templates that reference a CVE | hourly | MIT |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) | Entries that reference a CVE (IDs and links only) | every 6 h | GPL-2.0 |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Public proof-of-concept repositories per CVE | hourly | CC0-1.0 |

If a source is down, the last good copy is used and marked stale on the site; one failing feed
never stops a run. Details and required notices: [ATTRIBUTIONS.md](ATTRIBUTIONS.md).

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
[iCalendar: KEV due dates](https://raw.githubusercontent.com/markusweldon/cverdict/data/feeds/kev-due.ics)
(also served from the site under `/feeds/`).

Every file, every field, sharding and the versioning policy: [docs/DATA.md](docs/DATA.md).

## Deploy your own

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/markusweldon/cverdict)

**Vercel, zero config.** Import the repository and deploy. The site is static; `/data/*` and
`/feeds/*` are rewritten to the `data` branch on raw.githubusercontent.com, so fresh data arrives
every hour without a redeploy. A fresh clone reads this repository's data until you point the
rewrites in `vercel.json` at your own.

**GitHub Pages.**

1. Fork the repository and enable Actions on the fork.
2. Settings → Pages → Source: **GitHub Actions**.
3. Actions → **refresh-data** → Run workflow. From then on it publishes the data and redeploys
   the site every hour.

Renaming, custom domains, the optional `SITE_URL` variable and troubleshooting: [docs/DEPLOY.md](docs/DEPLOY.md).
Hosting costs nothing on either platform's free tier.

## Local development

Requires Node 22.12+, git and about 1 GB of disk.

```sh
npm ci
npx tsx scripts/mock-data.ts   # instant: a deterministic mock dataset in site/public/data
npm run pipeline               # or the real data: the first run clones cvelistV5 (~400 MB), a few minutes
npm run dev                    # http://localhost:5173
```

Both write to `site/public/data/`, which the dev server serves. Useful pipeline flags:
`--offline` (replay the cache), `--now 2026-10-26T19:30:00Z` (freeze time),
`--cvelist-dir` / `--poc-dir` (reuse existing clones). `npm test` and `npm run typecheck` run the
checks CI runs. More in [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

**v1.1**

- **Woke-up feed**: Quiet or Watch CVEs that just gained exploit evidence.
- **Backtest receipts**: a page showing how past verdicts held up against later KEV listings.
- **CNA noise panel**: who publishes how much, and how much of it ever matters.
- **EPSS sparklines** on CVE pages and rows.
- **Open Graph images** per CVE, so shared links carry the verdict.

**v2**

- **SBOM drop**: drop a CycloneDX or SPDX file and see your components in the signal, entirely in the browser.
- **MCP server**, so AI agents can ask for verdicts and their reasons.
- **Browser extension** that puts the verdict next to any CVE ID on the web.
- **MSRC exploitability index** as a chip for Microsoft CVEs.
- **EUVD cross-check** against ENISA's EU Vulnerability Database.

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

## Contributing

Bug reports, data-source proposals and score disputes are all welcome; each has an
[issue template](https://github.com/markusweldon/cverdict/issues/new/choose). Every CVE page has a
"Disagree?" button that opens a prefilled one. To change the weights, open a pull request with a
calibration diff: see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through
[private reporting](SECURITY.md).

## License

- **Code**: [MIT](LICENSE).
- **Data we create** (scores, tiers, reason chips, batches, stats): [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
- **Upstream data** stays under its own terms. CVE records are © The MITRE Corporation and used under
  the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse); the rest is listed in
  [ATTRIBUTIONS.md](ATTRIBUTIONS.md).

## Acknowledgements

CVErdict stands entirely on public work: the [CVE Program](https://www.cve.org/) and its CNAs;
CISA for [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
[Vulnrichment](https://github.com/cisagov/vulnrichment); the [FIRST EPSS SIG](https://www.first.org/epss/)
and Empirical Security; CERT/CC for [SSVC](https://github.com/CERTCC/SSVC); Rapid7 and the
[Metasploit](https://github.com/rapid7/metasploit-framework) community;
[ProjectDiscovery](https://github.com/projectdiscovery/nuclei-templates); OffSec's
[Exploit-DB](https://www.exploit-db.com/); [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub);
and Vercel for the [Geist](https://vercel.com/font) typefaces. None of them endorse this project.
