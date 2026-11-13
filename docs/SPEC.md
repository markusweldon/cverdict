# Build spec (v0.1)

This is the implementation contract for the project. Brand strings live in `shared/brand.ts`;
never hard-code them, import `BRAND`. The public data contract is `shared/contract.ts`; the scoring
weights and chip catalogue are `shared/model.ts`. Read all three first.

## 0. Principles

1. **Static and forkable.** The site and the data need no server, no accounts and no API keys. An hourly GitHub
   Actions job builds JSON; the site is a static SPA that reads it. Anyone can fork and run their own copy. One
   optional Vercel Function serves link-preview bots only (`api/share.ts`); people never reach it. The MCP server
   (`mcp/`) runs on the user's own machine and reads the same static files; nothing on the site depends on it.
2. **NVD-independent.** NIST stopped enriching most CVEs in April 2026. We use CVE List V5 (CNA + CISA-ADP
   containers), CISA KEV, EPSS and public exploit feeds.
3. **Explainable.** Every score is a sum of chips the user can read, each linked to its source. No ML, no LLM text.
   Unknowns are shown, never imputed. "Quiet" means *no evidence yet*, never "safe".
4. **Fail soft.** One source being down never breaks a run: use the last good copy, mark it stale, keep going.
5. **Untrusted input.** CVE text is attacker-controllable (real records contain `<script>`/`onerror` payloads).
   Render as text only. Never use `innerHTML`/`dangerouslySetInnerHTML`. Never render `supportingMedia`.

## 1. Repository layout

```
shared/            contract.ts  model.ts  shard.ts  brand.ts  cna.ts   (imported by both sides; no Node/DOM APIs)
                   verdict.ts  share.ts  share-images.ts        (verdict words and link-preview tags; .js imports)
                   versions.ts  packages.ts  mcp.ts             (version ranges and package keys; MCP copy)
api/               share.ts   (Vercel Function for link-preview bots; tests in api/_test/)
tools/og/          render.mjs (renders site/public/og/*.png by hand; own package.json and lockfile)
pipeline/
  src/
    cli.ts                 entry: parses flags, runs the pipeline, prints a summary
    run.ts                 orchestration (fetch → stream CVE list → enrich → score → emit → validate)
    ingest.ts              fetch every source, stream the CVE list once, normalise window ∪ KEV ∪ woke records
    config.ts              URLs, timeouts, window size, budgets
    util/                  http.ts (fetch w/ timeout+retry+cache), git.ts (clone, ls-tree, cat-file --batch),
                           csv.ts (RFC 4180), text.ts (sanitise/truncate), dates.ts, log.ts, zip.ts (bounded ZIP64)
    sources/               cvelist.ts  kev.ts  epss.ts  metasploit.ts  nuclei.ts  exploitdb.ts  poc.ts  osv.ts
    normalize.ts           CVE v5 JSON → NormalizedCve (internal type)
    score.ts               NormalizedCve + Enrichment → { score, tier, reasons, unknowns }
    batches.ts  stats.ts  changes.ts  woke.ts  receipts.ts  packages.ts  backtest.ts  state.ts  rows.ts  types.ts
    emit/                  build.ts (every output file, in memory)  json.ts  atom.ts  ics.ts
    validate.ts            schema/budget/sanity checks on the emitted tree
  test/                    vitest; fixtures/ with small real-looking records (incl. XSS payloads)
site/
  index.html  vite.config.ts  public/ (favicon.svg, robots.txt, theme-init.js, og/ share images; data/ is gitignored,
             written by the pipeline)
  src/       main.tsx  app.tsx  router.ts  data.ts  state.ts  format.ts  drill.ts  woke.ts  receipts.ts
             components/  pages/  styles/  check/ (SBOM and lockfile parsers, matching, session)
.github/workflows/  ci.yml  refresh.yml  release-mcp.yml
mcp/                read-only MCP server for AI agents (stdio), reading the published files
  src/                     data.ts (bounded, cached reads)  tools.ts (the six tools)  server.ts (factory)  stdio.ts
  test/                    vitest: fake-fetch unit, protocol and spawn tests; smoke.ts (CI, on mock data)
  package.json  README.md  LICENSE  LICENSE-THIRD-PARTY  server.json (MCP Registry)   the cverdict-mcp package on npm (0.1.0 was published by
                           hand; later versions come from release-mcp.yml)
scripts/            publish-data-branch.sh  mock-data.ts  validate-data.ts  calibrate.ts  backtest.ts  mcp-measure.ts
docs/               SPEC.md  SCORING.md  DATA.md  DEPLOY.md
vercel.json  README.md  ATTRIBUTIONS.md  LICENSE (MIT)  SECURITY.md  CONTRIBUTING.md
```

Single root `package.json` (ESM). Scripts: `pipeline` (tsx), `mock`, `calibrate`, `backtest`, `dev`, `build`, `preview`,
`test` and `test:watch` (vitest), `typecheck` (tsc), `mcp` (the MCP server from source), `build:mcp` (its single-file bundle).
Runtime deps: `preact` only. Pipeline uses only Node 22 built-ins (`fetch`, `zlib`, `child_process`, `fs`). The MCP
server's SDK (`@modelcontextprotocol/server`) and `zod` are exact-pinned dev dependencies, bundled into
`mcp/dist/cverdict-mcp.mjs`; the site never imports them (`shared/mcp.ts` holds the copy both use).

## 2. Pipeline

### CLI

```
npm run pipeline -- [--out site/public/data] [--previous <dir with previous v1/ output>] [--cache .cache]
                    [--cvelist-dir <existing cvelistV5 git clone>] [--poc-dir <existing PoC-in-GitHub clone>]
                    [--osv-dir <dir>] [--now 2026-10-26T19:30:00Z] [--window-days 30] [--knob 50]
                    [--refresh-backtest] [--offline]
```

- `--out`: output root. Writes `<out>/v1/...` and `<out>/feeds/...`. Default `site/public/data`.
- `--previous`: previous output root (the checked-out `data` branch). Used for `changes.json`, the carried
  `v1/state.json` (Woke Up tracking, the Receipts log) and the carried backtest in `receipts.json`. Missing is fine:
  each starts fresh.
- `--osv-dir`: read the OSV.dev dumps from `<dir>/<ecosystem>.zip` instead of downloading them.
- `--knob`: default knob for stored tiers (30 to 80, default 50).
- `--refresh-backtest`: recompute the hindsight backtest now instead of carrying it forward.
- `--cache`: cache dir. `<cache>/sources/` holds last-good raw downloads (+ `.meta.json` with etag/fetched_at);
  `<cache>/git/` holds clones.
- `--cvelist-dir` / `--poc-dir`: use an existing clone instead of cloning (local dev). Never modify it.
- `--now`: freeze "now" (tests, reproducible runs). Default: current time.
- `--offline`: never hit the network; use cache only (fail if missing).
- Exit code 0 when output was written and validated (even with stale sources); non-zero only when the CVE List
  could not be read at all or validation failed. On non-zero, nothing in `--out` is half-written: build into
  `<out>.tmp-<pid>` and rename at the end.

### Sources (primary → fallback; every source returns data + a `SourceStatus`)

| id | primary | fallback | parse | sanity |
|---|---|---|---|---|
| `cvelist` | `git clone --depth 1 --no-checkout --single-branch https://github.com/CVEProject/cvelistV5.git` into `<cache>/git/cvelistV5` (if it exists: `git fetch --depth 1 origin main` and use `FETCH_HEAD`) | none (fatal) | `git ls-tree -r -z <rev> cves/` → paths matching `cves/YYYY/NNxxx/CVE-*.json`; stream blobs with **one** `git cat-file --batch` process (write `<sha>\n`, read `<sha> blob <size>\n<bytes>\n`) | ≥ 300k records |
| `kev` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`, then cache | JSON | ≥ 1,000 entries; never < 98% of cached count |
| `epss` | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | `https://raw.githubusercontent.com/empiricalsec/epss_scores/main/<YYYY>/epss_scores-<YYYY-MM-DD>.csv.gz` for today, then yesterday, then cache | gunzip; first line `#model_version:v2026.06.15,score_date:2026-10-26T12:03:00Z`; then `cve,epss,percentile` | ≥ 200k rows |
| `metasploit` | `https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json` | cache | object of modules; `references[]` entries like `CVE-2024-1234`; keep `name, fullname, rank, type, path` | ≥ 3,000 modules |
| `nuclei` | `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json` | cache | **NDJSON**; `ID`, `Info.Severity`, `file_path` | ≥ 2,000 lines |
| `exploitdb` | `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | cache (GitLab rate-limits quickly; fetch at most every 6h; reuse cache if younger) | RFC 4180 CSV; columns `id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,...`; `codes` is `;`-separated and contains CVE IDs | ≥ 40k rows |
| `poc-github` | `git clone --depth 1 --no-checkout https://github.com/nomi-sec/PoC-in-GitHub.git` into `<cache>/git/poc` (or fetch) | cache clone as-is | `git ls-tree -r --name-only` → `YYYY/CVE-….json`; cat-file only IDs we need; each file is an array of GitHub repo objects (`html_url, stargazers_count, created_at, fork`) | ≥ 5,000 files |
| `osv` | per ecosystem (npm, PyPI, Maven, Go, crates.io, RubyGems, Packagist, NuGet): `https://storage.googleapis.com/osv-vulnerabilities/<eco>/modified_id.csv` head (Range requests to the cursor) and the changed `<eco>/<id>.json`; `<eco>/all.zip` every 7 days or without a copy, a failed one again after a day (`--osv-dir` reads local zips) | the mirror in `<cache>/sources/osv-mirror.json.gz`, per ecosystem | ZIP64 reader (`util/zip.ts`, bounded); records with a CVE alias from GHSA, PYSEC, GO, RUSTSEC, DRUPAL-CORE/CONTRIB only (`shared/packages.ts` ATTRIBUTION); compacted to ID, package names and event strings | ≥ about half of today's records per ecosystem; never < 90% of the cached copy. **Never scored** (`NON_SCORING_SOURCES`), only `v1/packages.json` |

HTTP helper: `fetch` with 60 s timeout, 3 retries (2 s, 4 s, 8 s), `User-Agent: <slug>-pipeline (+repo url)`,
conditional GET with stored ETag/Last-Modified, writes last-good body to cache only after the source's sanity
check passes. Honour `--offline`. The CA bundle is picked up from `NODE_EXTRA_CA_CERTS` automatically.

Ingestion of CVE List: one streaming pass over all records (~415k, ~4.5 GB of JSON). For each record:
- update history counters (by `cveMetadata.datePublished` month for PUBLISHED; `dateReserved` month for the
  reserved view; REJECTED counted by datePublished month when present, else dateUpdated); AI-credit month counter.
- keep the record (normalised) if PUBLISHED and `datePublished` ∈ window, **or** the ID is in KEV.
Memory: never hold raw JSON for more than the current record. Expect ~60–120 s.

### Normalisation (`NormalizedCve`, internal)

From `containers.cna` and `containers.adp[]` (ADP with `providerMetadata.shortName === 'CISA-ADP'`):
- `title` (cna.title), English description (`descriptions[]` lang starting `en`, else first) sanitised:
  strip C0/C1 control chars except `\n`, collapse whitespace, max 1,000 chars.
- CVSS: prefer CNA `cvssV4_0` > `cvssV3_1` > `cvssV3_0`, else CISA-ADP `cvssV4_0` > `cvssV3_1` > `cvssV3_0`, else CNA
  `cvssV2_0` (display only, never scored).
  Parse the vector into a map. Keep `source`.
- CNA exploit maturity: collect `E` from all CNA vectors (v3: `E:U/P/F/H`; v4: `E:U/P/A`). Ignore when
  `assignerShortName === 'VulDB'` (it stamps E:P on most vectors). Only v4 `E:A` (attacked) is exploitation
  (`vendor.exploited`, E family); v3 `E:F`/`E:H` say working exploit code exists, which is weaponization
  (`vendor.functional`, X family); `E:P` is `vendor.poc`.
- SSVC from CISA-ADP `metrics[].other` where `type === 'ssvc'`: `content.options[]` is a list of single-key
  objects (`Exploitation`, `Automatable`, `Technical Impact`); values lower-cased. Also `content.version`, `content.timestamp`.
- ADP KEV block: `metrics[].other.type === 'kev'` → treat as KEV-listed with `content.dateAdded` (fallback source).
- CWE ids from `problemTypes[].descriptions[].cweId`; affected `{vendor, product, purl?}` (max 10; skip `n/a`).
- credits text joined; tags (`cna.tags`); references (max 10 URLs, http(s) only).
- AI credit: first credit value matching (case-insensitive)
  `\b(claude|anthropic|openai|gpt-?\d+(\.\d+)?o?|codex|aardvark|big ?sleep|gemini|xbow|zeropath|depthfirst|striga|zerotrail|mythos|glasswing|llm|large language model|agentic|ai[- ](assisted|agent|powered|driven|discovered|found|security|scanner))\b`
  or a handle ending in `-ai`/`.ai` (e.g. `zerotrail-ai`, `striga.ai`). Two exclusions: `claude` directly followed by
  another capitalised word is a person ("Claude Ndanda") unless that word is Opus, Sonnet, Haiku, Code, Security, Fable,
  Mythos, Agent(s), AI or Anthropic; and `.ai` company domains whose researchers are people (`horizon3.ai`) do not
  count. Store ≤ 80 chars of the credit around the match, so the matched words are always visible.
- "In the wild" vendor text: English description matches
  `\b(exploited in the wild|exists in the wild|in the wild|aware of (a )?reports?|may have been exploited|limited,? (and )?(highly )?targeted attacks?|actively exploited|exploitation detected|has been exploited)\b`
  in at least one sentence that does not also match the negation
  `(\b(no|not|unaware|without)\b|n['’]t\b)[^.]{0,60}\b(exploit|in the wild)`.

### Enrichment indexes

- KEV map by CVE id; KEV vendor/product prior: canonical vendor tokens (lower-case, accents and parenthesised text
  dropped, a leading "the" and trailing legal/line-of-business words such as Inc, Corporation, Networks, Systems,
  Software, Foundation removed, a small alias table for renames), so "Juniper Networks" meets KEV's "Juniper"; the
  product key drops a leading vendor name ("Apache Tomcat" → tomcat). Counts by vendor and by vendor+product
  **excluding the CVE itself**. Match a CVE's affected entries (and, for KEV CVEs, its own KEV vendor/product)
  exactly, else against the longest KEV vendor whose tokens start the name ("Siemens Mobility" → Siemens; whole
  tokens only, so "Applied Signal" never matches Apple).
- EPSS map; exploit maps (metasploit modules by CVE, nuclei by CVE, exploitdb by CVE, poc repos by CVE).
- PoC vetting: drop forks; a repo is **vetted** if `stargazers_count ≥ 2` or it was created ≥ 3 days before now;
  ignore IDs that are not PUBLISHED; `hype` if > 50 repos created within 7 days of the first.

### Scoring (`score.ts`, model `shared/model.ts`)

```
age        = days since datePublished
E chips    = kev.listed | ssvc.active | vendor.exploited (v4 E:A) | vendor.itw  (any → exploited)
X family   = max of: x.metasploit 34, x.nuclei 30, x.exploitdb 28, epss.high 27*, vendor.functional 24
                     (v3 E:F/E:H), x.poc 20 (vetted ≥ 1), ssvc.poc 10, vendor.poc 10, epss.mid 8*
             * EPSS chips only when age ≥ 14 days (otherwise add info chip epss.cold if scored)
             if none: age ≥ 14, every exploit source and EPSS loaded this run and no unvetted PoC repo → x.none −14;
             else x.too_new (unknown, 0)
SEV        = sev.crit_net 13 (≥9.0 and AV:N) | sev.crit 6 (≥9.0) | sev.high 1 (7–8.9) | sev.low −13 (<7) | sev.none (unknown)
SSVC       = (ssvc.automatable 6 | ssvc.not_automatable −2) + (ssvc.total 8 | ssvc.partial −6) | ssvc.missing (unknown)
PRIOR      = prior.product 10 | prior.vendor 8 | prior.none −6
             | prior.unknown (unknown, 0) when the record names no vendor or KEV is unavailable this run
NOISE      = only if X ≤ 0, no E, no unvetted PoC repo and every exploit source and EPSS loaded:
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

Chip labels are specific and dated, e.g. `CISA KEV · added Oct 21 · due Oct 24`, `Metasploit: exploit/linux/http/foo (excellent)`,
`EPSS 14.2% · 99th pct`, `Critical 9.8 · network`, `3 PoC repos (2 vetted), unverified, may be malware`,
`Product in KEV (×4)`, `AI-credited: “Claude Opus 5”`, `Part of Microsoft patch day · Oct 13 (1,407)`
(`bulk release` instead of `patch day` for aggregator CNAs such as VulnCheck or VulDB; names from `shared/cna.ts`).
`reasons[]` carries every chip that fired (including the ones that lost within a family, with `points: 0`) plus
unknown chips; `unknowns[]` lists missing evidence in words. Unit-test every chip and the family rules.
In the row tables, `Row.c` holds up to 4 chip ids for display and `Row.r` every chip id that fired (family losers
included, unknown-polarity chips excluded) for filtering.

### Batches, stats, changes

- **Batches:** group window records by (`cna`, publish date UTC). Size ≥ 50 → `Batch`. `families` from the first
  affected product (max 8, with how many passed). `top` = 5 best rows. Each member gets the `batch` info chip
  and `Row.b`.
- **Stats:** `monthly` from the streaming pass + KEV `dateAdded` months; `daily` for the window's full UTC days,
  then today so far (published, passed = exploited+likely at default knob, exploited); `hourly` waterfall buckets across the window
  (`counts[h] = [exploited, likely, watch, quiet]`); `cnas` top 25 in window; `ai_credits` top 20 strings.
- **Changes:** compare with `<previous>/v1/index.json` (if present): an item when the tier rose, or a new E/X chip
  appeared. Merge with previous `changes.json`, drop items older than 7 days, newest first, cap 500.

### Emit (all JSON minified, UTF-8; `schema_version`, `generated_at` on every file)

```
v1/meta.json        Meta (incl. sources[])
v1/signal.json      RowTable: score ≥ SIGNAL_MIN_SCORE or exploited/weaponized, window only, sorted score desc then pub desc
v1/index.json       RowTable: every published CVE in the window, sorted pub desc
v1/cve/<xx>.json    CveShard for window CVEs ∪ KEV CVEs ∪ woke.json CVEs (256 shards via shardOf)
v1/batches.json     BatchesFile (newest first)
v1/kev.json         KevFile
v1/stats.json       StatsFile
v1/changes.json     ChangesFile
v1/woke.json        WokeFile: CVEs published before the window with new exploitation evidence in 30 days (pipeline/src/woke.ts)
v1/receipts.json    ReceiptsFile: forward log of KEV catches (pipeline/src/receipts.ts) + hindsight backtest (pipeline/src/backtest.ts)
v1/packages.json    PackagesFile: package versions the shard CVEs affect, from the OSV mirror (pipeline/src/packages.ts)
v1/state.json       internal carry-forward state, read back through --previous (pipeline/src/state.ts; unstable)
feeds/signal.xml    Atom: newest 100 exploited+likely CVEs (title "CVE-… · <vendor> <product> · <tier>", summary = top chips)
feeds/kev.xml       Atom: KEV additions, last 30 days
feeds/kev-due.ics   iCalendar: one all-day VEVENT per KEV due date in [today-7d, +60d] (UID stable per CVE)
feeds/woke.xml      Atom: up to 100 woke-up CVEs (KEV and Exploit-DB wakes first, PoC-only wakes only when Likely next or Exploited), one entry per CVE
```

Budgets (gzip, checked by `validate.ts`; warn at 80%, fail at 150%): meta ≤ 8 KB, signal ≤ 120 KB, index ≤ 1 MB,
each shard ≤ 80 KB, stats ≤ 80 KB, woke ≤ 64 KB, receipts ≤ 64 KB, packages ≤ 256 KB, state ≤ 1 MB, total files ≤ 300
(full list: `BUDGETS` in `pipeline/src/config.ts`). XML/ICS must be escaped properly (no raw CVE text in markup).

## 3. Site

Vite + Preact + TypeScript SPA. No UI framework, no chart library. Hand-written CSS with design tokens.
Self-hosted fonts via `@fontsource-variable/geist` and `@fontsource-variable/geist-mono`.

**Data loading** (`data.ts`): base = `${import.meta.env.BASE_URL}data/v1/`. Fetch `meta.json` + `signal.json` +
`stats.json` + `batches.json` + `kev.json` + `changes.json` + `woke.json` for Today; `index.json` lazily (Explore, or
knob < 35); `woke.json` and `receipts.json` on their pages; `packages.json` only on the first interaction with the
Check Deps input card; shards on demand per CVE (cache in memory). Show a skeleton while loading and a friendly error state with retry.
If a CVE isn't in our shards, show "Outside the 30-day window" with links to cve.org / the raw record.

**Routing** (`router.ts`): History API, base-path aware (`import.meta.env.BASE_URL`), intercept same-origin `<a>` clicks.
Routes: `/` Today · `/cve/:id` · `/kev` · `/woke` · `/receipts` · `/batches` · `/explore` · `/check` · `/surge` · `/method` · `/feeds` · `/mcp`.
Unknown → 404 view. Update `document.title` per route.

**Pages**
- **Today (`/`)**: (1) ticker strip (published 24h · passed 24h · KEV due ≤72h · batches this week · data age); (2) hero
  noise meter: big mono numbers counting up: "14,281 new CVEs published → 312 worth your time" under "Last 30 days · Oct 5 – Nov 4" with a % and
  "1 in N"; (3) **signal waterfall**: Canvas spectrogram of the window (x = hour, stacked ticks; quiet ticks dim
  grey, passed ticks glow in tier colour; hover tooltip with hour + counts; re-colours live as the evidence bar turns;
  a column opens Explore for the UTC day it starts on (`/explore?day=YYYY-MM-DD&sort=score`): click, or Enter on
  the focused chart (`role="slider"`, arrow keys pick a column); on touch the first tap selects and the tooltip's
  "See Oct 13" link opens it; spike labels link to their batch card on `/batches`);
  (4) the **evidence bar**: rotary control (`role="slider"`, 35 to 65 on the site, arrow keys ±5, presets
  Broad 40 / Balanced 50 / Strict 60, each with its live count a day, and under them the backtest at the current
  setting: "Flagged 40 of 125 recent KEV additions before CISA did.", linked to Receipts), URL param `?knob=` (values outside 35 to 65
  open at the nearest end); (5) signal feed: rows (tier pill, mono CVE ID, vendor · product, title, top chips, score, age,
  batch tag); filter bar (tier, vendor search, hide WordPress / kernel / AI toggles, watchlist); (6) batch cards
  ("Microsoft · Oct 13 · 1,407 → 1 exploited · 2 PoC · 58 likely"); (7) KEV Clock strip; (8) "what changed" list;
  (9) Woke Up card: old CVEs that woke up in the last 7 days, most urgent first.
- **CVE (`/cve/:id`)**: verdict line ("Patch now: exploited, KEV due Oct 29" / "Likely next: Metasploit module" /
  "Watch" / "Quiet: no evidence yet (quiet ≠ safe)"); score dial with the arithmetic (base + each chip = total);
  chips grouped by family with sources and links; unknowns; evidence timeline; facts table (CNA, CVSS vector, CWE,
  affected, SSVC, EPSS, KEV); references; buttons: Copy as ticket (Markdown), Copy link, JSON, cve.org, "Disagree?"
  (GitHub issue link prefilled).
- **KEV Clock (`/kev`)**: due within 72h / overdue (≤7d) / this month; live countdowns; ransomware & forensic flags; ICS link.
- **Woke Up (`/woke`)**: CVEs published before the window that gained exploitation evidence in the last 30 days
  (`woke.json`), grouped by week, most urgent first at the evidence bar; `?kind=` filters by signal kind; each row shows its
  dated signals; notes say since when first-seen kinds are tracked and what the last run could not check; links to
  `woke.xml`.
- **Batches (`/batches`)**: cohort cards with tier bars; expand to families and top CVEs.
- **Receipts (`/receipts`)**: how often CVErdict, CVSS 7 or more and EPSS 10% or more flagged a CVE before CISA
  listed it (`receipts.json`). Two parts, never mixed: the forward log, and the 180-day backtest marked as hindsight,
  with strict and "with undated evidence" columns. Every figure shows its n.
- **Explore (`/explore`)**: all window CVEs; virtualised list (render only visible rows); search (ID/vendor/product/title),
  filters (tier, CNA, vendor, chip, publish day `?day=YYYY-MM-DD` shown as a removable "Published Oct 13" chip;
  an invalid day is ignored), sort (score/date); URL-synced.
- **Check Deps (`/check`)**: an SBOM (CycloneDX JSON or XML, SPDX JSON or tag-value, package URLs) or a lockfile is read
  in the browser (`check/parse.ts`) and matched against `packages.json` with `shared/versions.ts` (`check/match.ts`);
  results grouped by tier at the evidence bar, then "possibly affected, not confirmed", "not checked" and "not affected by a
  tracked CVE". `packages.json` loads on the first interaction with the input card, never on page open; nothing from the
  file goes into a request, the URL, history or storage; file text renders in the system monospace font
  (`--font-mono-system`) so no web font subset is fetched for it; rows do not prefetch shards; results stay in module
  memory until Clear or reload (`check/session.ts`). Caps: files 50 MB, pasted text 5 MB, lines 64 KB in line formats.
  The chunk is not warmed on other pages.
- **The Surge (`/surge`)**: monthly published since 1999 (SVG area/line, log toggle, Published/Reserved toggle),
  KEV additions per month overlay, AI-credited line, daily published vs passed for the window, top CNAs table.
- **Method (`/method`)**: how it works, the formula, the chip table generated from `shared/model.ts`, sources status
  from `meta.sources` (fresh/stale), blind spots ("Not in KEV ≠ not exploited", "exposure is yours"), attributions.
- **Feeds & API (`/feeds`)**: JSON API, Atom, ICS links with copy buttons and example `curl`/`jq`; section `#mcp` (kept
  for old links) points to the MCP Server page.
- **MCP Server (`/mcp`)**: how to add the MCP server to an agent from npm (`npx -y cverdict-mcp`), with a clone as the
  last option; the six tools with their descriptions; where it reads from; its limits (snippets and tool copy from
  `shared/mcp.ts`).

**Interactions**: keyboard: `j`/`k` move selection, `Enter`/`o` open, `/` focus search, `w` watch vendor,
`c` copy ticket, `?` shortcuts help, `⌘K`/`Ctrl+K` command palette (jump to CVE id, vendor, page).
Watchlist (vendors/products) in `localStorage` (try/catch) and `?watch=`; watched items always show, whatever the evidence bar.
"Since your last visit" badge from `localStorage` timestamp. Respect `prefers-reduced-motion`.

**Visual direction**: "SDR console meets Linear". Dark by default with a light theme toggle (and
`prefers-color-scheme`). Tokens (dark / light):

| token | dark | light |
|---|---|---|
| bg / surface / raised / border | `#0A0B0D` / `#111317` / `#171A1F` / `#23272E` | `#FAFAF9` / `#FFFFFF` / `#F4F4F2` / `#E4E4E0` |
| text / muted / faint | `#E6E8EB` / `#8A919C` / `#5B616B` | `#16181C` / `#5B616B` / `#8A919C` |
| accent (signal) | `#C6F432` | `#4D7C0F` |
| exploited / likely / watch / quiet | `#FF4D4F` / `#FF8A3D` / `#F5C542` / `#3A3F47` | `#D92D20` / `#C2410C` / `#A16207` / `#9CA3AF` |
| ai / ok | `#8B7CFF` / `#3DD68C` | `#6D28D9` / `#15803D` |

Geist Mono with tabular numerals for IDs, numbers and scores; Geist Sans for UI. Chips: 1px border on a 10–14% tint,
icon + text (never colour alone). Subtle grain/scanline texture on the hero, soft glow on passed items. Motion: count-up
600 ms, list re-filter 150 ms, respect reduced motion. Mobile: single column, sticky evidence bar, details full-screen.
Accessibility: WCAG AA contrast, focus rings, semantic landmarks, labelled controls.

**Security**: no `innerHTML`; external links `rel="noopener noreferrer nofollow"` + `target="_blank"`; only http(s)
URLs are linkified; CSP meta tag in `index.html`:
`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';
connect-src 'self' https://raw.githubusercontent.com; object-src 'none'; base-uri 'self'; form-action 'none'`.

**Budgets**: initial JS ≤ 90 KB gzip, CSS ≤ 25 KB gzip, fonts ≤ 2 woff2 files preloaded (latin subset).

## 4. Hosting & automation

- **Data branch.** `refresh.yml` runs hourly (`17 * * * *`) and on dispatch. Scheduled runs only do work in the
  canonical repository or when the repository variable `REFRESH_SCHEDULE` is `on`. GitHub starts scheduled runs late
  or skips them, so an external timer can also call the `workflow_dispatch` API every hour at minute 47
  (docs/DEPLOY.md, "Reliable hourly refresh"); the schedule gate does not apply to dispatched runs. Jobs:
  - `build` (`contents: read`, `pages: read`): checkout → `npm ci` → detect Pages → restore `.cache/sources`
    (actions/cache, key per run, restore-keys prefix) → fetch the current `data` branch without a token into
    `published/` (if it exists) → `npm run pipeline -- --out out --previous published --cache .cache` → save
    cache → upload `out/` as an artifact.
  - `publish` (`contents: write`, the only job with a write token; runs no npm code): fresh checkout → download
    the artifact → `scripts/publish-data-branch.sh out` (orphan commit, force-push to `data`; skip when the
    content hash is unchanged). The README it writes reproduces the CVE Terms of Use notice.
  - `pages` (after `publish`, only if GitHub Pages is enabled with source "GitHub Actions"): build the site with
    `BASE=/<repo>/`, put the artifact into `site/dist/data/` (and `feeds/` → `site/dist/feeds`), copy
    `index.html` to `<route>/index.html` for the static routes and to `404.html` for the rest, deploy with
    `actions/upload-pages-artifact` + `actions/deploy-pages`.
  - `watchdog`: checks the published `meta.json` for staleness and source health after every run that was not
    skipped by the schedule gate.
- **Vercel.** `vercel.json`: build `npm run build`, output `site/dist`; rewrites `/data/:path+` and the feed files
  `/feeds/*.xml|ics` to `https://raw.githubusercontent.com/<repo>/data/...`, then a last catch-all SPA fallback
  `/(.*)` → `/index.html` (rewrites apply after static files, so `/feeds` is the Feeds & API page); security headers
  (CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `frame-ancestors 'none'`).
  Result: zero-config: import the repo in Vercel, and fresh data arrives hourly without redeploys.
- **Link previews.** A rewrite just before the catch-all sends `/cve/<CVE ID>` to `api/share.ts` only when
  the `user-agent` header matches a link-preview bot (`BOT_UA_TOKENS` in `shared/share.ts`). The function returns
  `index.html` with that CVE's `<title>`, description, Open Graph and Twitter tags between the share markers,
  built from its detail shard, under one 1.5 s deadline, and the static site card on any failure. The four tier
  images and the site card are static PNGs in `site/public/og/`. Details and costs: docs/DEPLOY.md.
- **CI.** `ci.yml` on push/PR: `npm ci`, `npm run typecheck`, the link-preview function checked and imported as Node
  ESM, `npm test`, `npm run build` and a check of the built share block, `npm run build:mcp` and an MCP smoke test of
  the bundle on mock data (`mcp/test/smoke.ts`), `shellcheck`, the data-branch publisher test and the `vercel.json`
  JSON check.
- **MCP releases.** `release-mcp.yml` on a tag `mcp-v<version>`: a read-only job checks the tag against
  `mcp/package.json`, runs the typecheck, the MCP tests and the smoke test, and packs the bundle; a second job, which
  runs none of that code, publishes the tarball to npm through trusted publishing (OIDC, with provenance); a third
  lists the version on the MCP Registry from `mcp/server.json` (GitHub OIDC login, `mcp-publisher` pinned and
  checked against its Sigstore bundle).
