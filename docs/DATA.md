# Open data API

Everything CVErdict shows is published as static JSON and feeds, rebuilt every hour, free to use
without a key. The TypeScript types are the contract: [`shared/contract.ts`](../shared/contract.ts).
This page explains them.

```sh
# Raw files on the data branch (CORS: any origin)
https://raw.githubusercontent.com/markusweldon/cverdict/data/v1/meta.json
# The same files through the site
https://cverdict-psi.vercel.app/data/v1/meta.json
```

Our scores, tiers, chips and statistics are CC0-1.0. Text and data copied from upstream sources
(CVE descriptions, KEV entries, EPSS scores, package advisories) stay under their own terms: see
[ATTRIBUTIONS.md](../ATTRIBUTIONS.md).

## Files

| Path | Type in `contract.ts` | Contents | Size (gzip) |
|---|---|---|--:|
| `v1/meta.json` | `Meta` | Run metadata, headline counts with definitions, source health | ~2 KB |
| `v1/signal.json` | `RowTable` | Window CVEs with score ≥ 35, plus every exploited or weaponized one; score desc, then newest | ~55 KB |
| `v1/index.json` | `RowTable` | Every CVE published in the window; newest first | ~720 KB |
| `v1/cve/<xx>.json` | `CveShard` | Full detail for window CVEs, every KEV CVE and every CVE in `woke.json`; 256 shards | ~25–50 KB each |
| `v1/batches.json` | `BatchesFile` | Batches (patch days and bulk releases) in the window; newest first | ~30 KB |
| `v1/kev.json` | `KevFile` | KEV entries added in the last 30 days or due from 14 days ago on; newest first | ~4 KB |
| `v1/stats.json` | `StatsFile` | Monthly history since 1999, daily and hourly window counts, top CNAs, AI credits | ~6 KB |
| `v1/changes.json` | `ChangesFile` | Escalations in the last 7 days; newest first | ~1 KB |
| `v1/woke.json` | `WokeFile` | CVEs published before the window that gained exploitation evidence in the last 30 days; newest wake first | ~25 KB |
| `v1/receipts.json` | `ReceiptsFile` | Receipts: KEV additions each method flagged before CISA listed them, from the forward log and the hindsight backtest | ~20 KB |
| `v1/packages.json` | `PackagesFile` | Package versions affected by the CVEs that have a detail shard (window, KEV, woke up), from OSV.dev advisories, with each CVE's row | ~120 KB |
| `v1/state.json` | — | **Internal and unstable.** State carried from one run to the next; do not build on it | ~35 KB, growing to ~0.55 MB |
| `feeds/signal.xml` | Atom | Newest 100 Exploited and Likely-next CVEs | ~20 KB |
| `feeds/kev.xml` | Atom | KEV additions, last 30 days | ~5 KB |
| `feeds/kev-due.ics` | iCalendar | One all-day event per KEV due date from 7 days ago to 60 days ahead | ~2 KB |
| `feeds/woke.xml` | Atom | Up to 100 CVEs from `woke.json`: every KEV and Exploit-DB wake first, PoC-only wakes only when Likely next or Exploited | ~10 KB |

The **window** is the 30 days before `meta.generated_at` (`meta.window`). Sizes are from the
2026-10-26 run (15,790 window CVEs); `index.json` grows with CVE volume, about 47 bytes gzip per
CVE. The pipeline warns near a file's size budget and fails a run rather than publish files far
over it.

## Conventions

- Minified UTF-8 JSON. Every JSON file has `schema_version` (currently `1`) and `generated_at`
  (the run's time, ISO 8601 UTC).
- Date-times are ISO 8601 UTC (`2026-10-26T19:30:00.000Z`); calendar dates are `YYYY-MM-DD`.
- Missing values are `null`, never omitted, except the optional `Reason.url` and `Reason.at`.
- **All text is plain text and attacker-controllable.** CVE titles and descriptions are written
  by CNAs and sometimes contain HTML or script payloads. Never render them as HTML. Reference
  links are filtered to `http(s)` URLs, but they still point at third-party content.
- **Chip ids are stable, labels are not.** Use `Reason.id` (and `polarity`, `points`) in code;
  labels are for humans and change wording freely.

## Row tables: `index.json`, `signal.json`

List files are columnar to stay small: `rows[i][j]` is the value of column `cols[j]`.

```json
{
  "schema_version": 1,
  "generated_at": "2026-10-26T19:30:00.000Z",
  "scope": "score >= 35 or exploited/weaponized; published in the last 30 days",
  "cols": ["id","pub","cna","v","p","t","s","tier","x","w","k","ai","c","r","cv","e","kd","b"],
  "rows": [["CVE-2026-107656","2026-10-26T13:45:03Z","fortinet","Fortinet","FortiSandbox","An authentication bypass…",76,"likely",0,0,0,0,
            ["vendor.functional","sev.crit_net","prior.product","ssvc.total"],
            ["vendor.functional","sev.crit_net","ssvc.total","ssvc.automatable","prior.product"],9.6,null,null,null]]
}
```

| Column | Type | Meaning |
|---|---|---|
| `id` | string | CVE ID |
| `pub` | string | `datePublished`, ISO 8601 UTC |
| `cna` | string | CNA short name (`assignerShortName`) |
| `v`, `p` | string | Vendor and product of the first affected entry (`""` if unknown) |
| `t` | string | Title, or the description cut to 160 characters |
| `s` | number | Evidence score, 0–100 |
| `tier` | string | `exploited` \| `likely` \| `watch` \| `quiet` at the default knob |
| `x` | 0 \| 1 | Any confirmed-exploitation (E) chip fired |
| `w` | 0 \| 1 | Weaponized: a Metasploit module or Nuclei template exists |
| `k` | 0 \| 1 | In CISA KEV |
| `ai` | 0 \| 1 | The CNA credits an AI system or lab (information only) |
| `c` | string[] | Up to 4 chip ids for display, strongest first, positive before negative |
| `r` | string[] | Every chip id that fired, including chips that lost within their family; unknown chips left out. Filter on this, not on `c` |
| `cv` | number \| null | CVSS base score (CNA first, then CISA-ADP) |
| `e` | number \| null | EPSS probability, 0–1 |
| `kd` | string \| null | KEV due date |
| `b` | string \| null | Batch id, when the CVE belongs to a patch-day batch |

Map columns by name from `cols`, not by position. In TypeScript, `rowsFromTable()` from
`shared/contract.ts` does it; in jq:

```sh
jq '.cols as $c | [.rows[] | [$c, .] | transpose | map({(.[0]): .[1]}) | add]' signal.json
```

To re-tier at another knob, use `tierFor(s, x === 1, w === 1, knob)` from `shared/contract.ts`:
Exploited when `x`; else Likely next when `w` or `s ≥ knob`; else Watch when `s ≥ 25`; else Quiet.

## `meta.json`

| Field | Meaning |
|---|---|
| `score_model` | Version of the scoring model (`shared/model.ts`), e.g. `v0.1.0` |
| `knob_default` | Knob used for every stored `tier` (default 50) |
| `window` | `{ from, to, days }` of the window |
| `counts` | Headline numbers, below |
| `definitions` | A plain-language definition of every key in `counts` |
| `sources[]` | One `SourceStatus` per upstream source, below |

`counts`: `window_published`, `window_passed` (Exploited + Likely next), `window_by_tier`,
`published_24h`, `passed_24h`, `published_7d`, `passed_7d`, `published_mtd`, `published_ytd`,
`rejected_window`, `kev_total`, `kev_adds_30d`, `kev_adds_mtd`, `ai_credited_window`,
`batches_window`. Read `definitions` for the exact meaning of each, rather than guessing.

`SourceStatus`:

| Field | Meaning |
|---|---|
| `id` | `cvelist`, `cisa-adp`, `kev`, `epss`, `metasploit`, `nuclei`, `exploitdb`, `poc-github`, `osv` |
| `name`, `url`, `license` | What the source is and its terms |
| `ok` | Usable data was available this run. When `false`, scores show that source's evidence as unknown (`prior.unknown`, `x.too_new`), never as absent. `osv` is the exception: it only feeds `packages.json`, never a score, so its health never changes a CVE |
| `stale` | The live fetch failed and the last good copy was used |
| `fetched_at` | When that copy was downloaded (for git sources: the upstream commit time) |
| `upstream_version` | KEV catalog version, EPSS model and date, git commit, … |
| `records` | Number of records parsed |
| `error` | Why the fetch failed, if it did |

`osv` sums up eight ecosystems (their own health is in `packages.json` `sources[]`): `ok` when at
least one has a copy, `stale` when any is stale or has none, `fetched_at` the oldest copy's time,
`records` the advisories in the copies.

## `cve/<xx>.json` and sharding

Per-CVE detail is split into 256 shards. The shard of an ID is the FNV-1a 32-bit hash of the
trimmed, upper-cased ID, modulo 256, as two lower-case hex digits (`shared/shard.ts`):

```ts
function shardOf(id: string): string {
  let h = 0x811c9dc5;
  for (const ch of id.trim().toUpperCase()) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193);
  return ((h >>> 0) % 256).toString(16).padStart(2, '0');
}
// shardOf('CVE-2026-96951') === 'a5'
```

```sh
# The same in Python, for scripts
python3 -c 'import sys,functools as f;print("%02x"%(f.reduce(lambda h,c:((h^ord(c))*16777619)&0xffffffff,sys.argv[1].upper(),2166136261)%256))' CVE-2026-96951
```

Every shard file exists, even an empty one, so a lookup never 404s on a valid shard. A CVE that is
not in the window, not in KEV and not in `woke.json` is not in any shard. The file is
`{ schema_version, generated_at, items: { "<CVE ID>": CveDetail } }`.

`CveDetail`:

| Field | Meaning |
|---|---|
| `id`, `state` | CVE ID; always `PUBLISHED` (rejected records are not emitted) |
| `published`, `reserved`, `updated` | Dates from `cveMetadata` |
| `cna`, `title`, `description` | CNA short name; title (or `null`); English description, plain text, ≤ 1,000 characters |
| `cvss` | `{ version, score, severity, vector, source: "cna" \| "cisa-adp" }` or `null` |
| `cwe` | CWE ids |
| `affected` | Up to 10 `{ vendor, product, purl }` |
| `ssvc` | CISA SSVC `{ exploitation: none\|poc\|active, automatable: yes\|no, technical_impact: partial\|total, version, timestamp }` or `null` |
| `kev` | `{ date_added, due_date, ransomware: Known\|Unknown, forensic_triage, name, required_action, notes }` or `null` |
| `epss` | `{ score, percentile, date, model }` or `null` |
| `exploits` | `metasploit[]` (`name, fullname, rank, type, url, date`: the module's disclosure date or `null`), `nuclei[]` (`path, severity, url`), `exploitdb[]` (`id, verified, url, date`), `poc` (`count, vetted, hype, top[]` with `url, stars, created`) |
| `ai_credit` | Up to 80 characters of the CNA credit around the name of an AI system or lab, or `null` |
| `tags` | CNA tags such as `disputed`, `unsupported-when-assigned` |
| `batch` | Batch id or `null` |
| `score` | `{ value, tier, raw, model }`: `raw` is the score before the exploitation floor and clamping |
| `reasons[]` | Every chip, ordered E, X, SEV, SSVC, PRIOR, NOISE, then info and unknown chips |
| `unknowns[]` | Evidence we could not see, in words |
| `timeline[]` | `{ at, event, source }`, oldest first |
| `references[]` | Up to 10 reference URLs from the CNA |
| `woke` | `{ at, signals[] }` when the CVE is in `woke.json` (same fields as there), else `null` |

A `Reason` is `{ id, label, polarity: up|down|info|unknown, family: E|X|SEV|SSVC|PRIOR|NOISE|INFO, points, source, url?, at? }`.
Chips that lost to a stronger one in their family are included with `points: 0`, so
`15 + Σ points` equals `score.raw` for a CVE that is not exploited (`score.value` is that clamped to
0–100, so the two differ only when `raw` is negative), and equals `score.value` for an exploited
CVE, whose E chips carry the +75, the floor of 90, the cap and the ransomware bonus. Every chip id
is listed in [SCORING.md](SCORING.md#chips-and-points).

PoC repository links are third-party, unverified, and may be malware.

## `batches.json`

`{ schema_version, generated_at, min_size: 50, batches: Batch[] }`. A batch is 50 or more CVEs from
one CNA published on one UTC day, such as a Patch Tuesday.

| Field | Meaning |
|---|---|
| `id` | `<cna slug>-<YYYY-MM-DD>`, e.g. `microsoft-2026-10-13` |
| `cna`, `date`, `count` | Who, which day, how many |
| `by_tier` | Count per tier at the default knob |
| `families` | Up to 8 most common products: `{ name, count, passed }` |
| `top` | Up to 5 highest-scoring rows (objects, not columnar) |

## `kev.json`

`{ schema_version, generated_at, catalog_version, entries: KevEntry[] }`, newest addition first.
Entries: `id, vendor, product, name, date_added, due_date, ransomware, forensic_triage,
description, required_action`, plus `in_window` (the CVE was published in the window) and `score`
(our score, if we have the record).

## `stats.json`

| Field | Meaning |
|---|---|
| `monthly[]` | Every month since 1999: `{ month, published, reserved, rejected, ai, kev_added }`. `published` counts records in PUBLISHED state by `datePublished`, and `reserved` buckets the same records by their reservation month. `rejected` counts REJECTED records by `datePublished`, else by rejection date (most were never published). `ai` counts published records that credit an AI system or lab |
| `daily[]` | Each full UTC day of the window, then today so far, oldest first: `{ date, published, passed, exploited }`. The partial day the window starts in is left out |
| `hourly` | `{ start, hours, counts }`: `counts[h]` is `[exploited, likely, watch, quiet]` for hour `h` after `start` |
| `cnas[]` | Top 25 CNAs in the window: `{ cna, count, passed, no_cvss, ssvc_missing }` |
| `ai_credits[]` | Top 20 AI credit excerpts (≤ 80 characters, as in `ai_credit`): `{ text, count }` |

## `changes.json`

`{ schema_version, generated_at, items: Change[] }`: escalations in the last 7 days, newest first,
at most 500. An item is recorded when a CVE's tier rose, or a new exploitation or exploit chip
appeared, between two hourly runs: `{ id, at, from, to, added }`. `from` is `null` for a CVE seen for
the first time; `added` lists the chip ids that appeared.

## `woke.json`

Old CVEs that woke up: published before the 30-day window, with new exploitation evidence in the
last 30 days (`days`). The window views cannot show them.

| Field | Meaning |
|---|---|
| `since` | Signals dated from this instant on count (`generated_at` minus `days`) |
| `days` | Length of that period, 30 |
| `published_before` | Only CVEs published before this instant (the window start) are included |
| `tracking` | `{ metasploit, nuclei, epss }`: since when each first-seen kind is tracked, or `null` when it is not tracked yet. Evidence that was already there when tracking started is not listed, and counts as older exploit evidence |
| `skipped[]` | `{ kind, reason }` for each signal this run could not check. Missing data is never read as "nothing new" |
| `counts` | Items with at least one signal of each kind |
| `items[]` | `{ id, at, signals[], row }`, newest `at` first, at most 500. `at` is the date of the newest signal; `row` is a `Row` (the same fields as in the row tables, as an object) |

A signal is `{ kind, at, first_seen, label, source, url }`:

| `kind` | Fires when | `at` |
|---|---|---|
| `kev` | The CVE was added to CISA KEV | KEV `dateAdded` (YYYY-MM-DD) |
| `exploitdb` | The CVE's first Exploit-DB entry was added | Exploit-DB `date_added` (YYYY-MM-DD) |
| `poc` | The CVE's first PoC repo on GitHub that is at least 3 days old or has 2 stars appeared (the rule of the `x.poc` chip; the code is not checked) | the repo's `created_at` |
| `metasploit` | The CVE's first Metasploit module appeared | first seen: the run that first saw it |
| `nuclei` | The CVE's first Nuclei template appeared | first seen: the run that first saw it |
| `epss` | EPSS is at least 10% and at least 3× its score 30 days before the current score date | first seen: the EPSS score date of the run that first saw the jump (YYYY-MM-DD) |

- Each kind is "first of its kind": a second Metasploit module or a tenth PoC repo does not wake
  a CVE up again.
- `first_seen: true` means the source has no date for the evidence (Metasploit's `mod_time` is a
  modification time, Nuclei's index has no dates, two daily EPSS files cannot say which day the
  score rose), so `at` is when the pipeline first saw it. These kinds need the previous run's
  state; without it everything already present is treated as known, so a first run never dates
  old evidence as new. The same restart happens for Metasploit or Nuclei when the last run that
  compared a fresh copy of that source is more than 48 hours ago (it was down, or only a stale
  cached copy loaded): what appeared meanwhile cannot be dated. A stale copy never dates anything
  and puts the kind in `skipped`.
- The exploit kinds (`exploitdb`, `poc`, `metasploit`, `nuclei`) only wake a CVE that had no
  public exploit evidence before the period: no earlier Exploit-DB entry, PoC repo or KEV listing,
  no Metasploit module with an earlier `mod_time`, and no Metasploit module or Nuclei template that
  the tracking knew without first seeing it in the period. A module or template that was already
  there when tracking started or restarted has no date, so it counts as older evidence. An old
  `mod_time` does not count when that module is the CVE's first and was first seen in the period:
  a module can land in Metasploit weeks after its last commit. A first PoC repo for a CVE with a
  Metasploit module from 2015 is not a wake. `kev` and `epss` signals always count.
- The EPSS check needs the EPSS file from 30 days before the current score date. When it cannot be
  loaded, or the two files come from different EPSS models (a new model moves many scores at once),
  the check is skipped and `skipped` says so. After a pause of more than 48 hours, jump tracking
  restarts from a baseline, so jumps from the pause are not all dated on the day it resumes.
- Evidence only counts when it arrived after the CVE was already older than the window, so a CVE
  does not join the list by ageing out of the window. Signals with a time (`poc`, first-seen
  kinds) are compared to the minute; date-only ones (`kev`, `exploitdb`, `epss`) by UTC day. A CVE
  that was in KEV before the period, or while it was still in the window, is left out: it never
  fell asleep. After an exploit artifact from while it was still in the window, no later artifact
  counts as its first.
- `label` is our own plain text, written to read after "Woke up Oct 30:" (e.g. `added to CISA KEV`).
  `url` links the evidence where a stable link exists (KEV catalog search, Exploit-DB entry,
  Metasploit module, Nuclei template, the PoC-in-GitHub index file, the FIRST EPSS time series).

```sh
# What woke up this week, with the evidence
curl -s $BASE/woke.json | jq -r --arg since "$(date -u -d '-7 days' +%F)" '
  .items[] | select(.at >= $since) | "\(.at[:10])  \(.id)  \(.row.tier)  \(.signals | map(.label) | join("; "))"'
```

## `receipts.json`

How often a CVE that CISA later added to KEV had already been flagged, by three methods with the
same definitions: `cverdict` (Exploited or Likely next at the default knob, 50), `cvss7` (the CVSS
base score the site shows, CNA else CISA-ADP, is 7.0 or more) and `epss10` (EPSS is 10% or more; a
CVE without an EPSS score is not flagged). Two parts, never mixed: the **forward log**, recorded in
real time, and the **backtest**, rebuilt after the fact and marked `hindsight: true`.
`definitions` repeats each rule in words. Every count comes with its `n`; nothing is rounded away.

| Field | Meaning |
|---|---|
| `score_model`, `knob` | Score model and knob the `cverdict` method uses |
| `definitions` | Plain-language definition of each method and figure |
| `forward` | `ForwardReceipts`, below |
| `backtest` | `BacktestReceipts`, below, or `null` until the first backtest |

A `MethodScore` is `{ method, n, before, earlier, same_day, lead }`: of `n` KEV additions, `before`
were flagged before the listing, `earlier` at least one whole day before the KEV `dateAdded`
and `same_day` on that date (0 days, counted apart). `lead` is `{ median, q1, q3 }` in days over
the `before` CVEs (linear interpolation between ranks), or `null` when `before` is 0. An
`AlertVolume` is `{ method, n, flagged }`.

### The forward log (`forward`)

Every run records, for each CVE in the window, the time of the first run that saw it and of the
first run at which each method flagged it, to the minute (runs can come twice an hour). When one
of those CVEs appears in KEV, at any age, the run records its `dateAdded` and when it first saw
the listing. KEV gives a date without a time; we read it as a US Eastern day (CISA's own time
zone), so a run time is compared with it by its Eastern day: a CVE first seen at 00:17 UTC counts
as seen on the Eastern day before.

- **Flagged before the listing** means flagged by a run earlier than the one that first saw the
  listing, on or before the KEV `dateAdded`. A flag that came with the listing (the `kev.listed`
  chip, or EPSS reacting to it) is never "before". Same definition for every method. When a run can
  see a listing it cannot record (a CISA-ADP KEV block without a date), no flag of any method is
  recorded until the listing is. A same-day flag can still come from CISA's own update to the record made as
  it lists the CVE (for example SSVC exploitation "active"), which is one reason it is counted apart.
- **Counted** (`eligible`): KEV additions dated from the `since` day on, for CVEs the log saw in an
  earlier run, on or before the listing date. The rest are in `uncounted`: `older` (the CVE was not
  in the log, because it was published before the window when the log could have seen it; Woke up
  covers these), `listed_first` (CISA listed it before, or in the same run as, our first sighting)
  or `no_record` (no published CVE record yet).
- Each CVE is **watched while it is in the window**. A method that flags it only later is not
  counted, for every method alike.
- **Alert volume** (`volume`): out of every CVE the log has watched, how many each method flagged at
  least once. CVEs still in the window can still be flagged, so these shares can rise a little.
- The log starts with the first run that keeps it (`since`) and never fills in anything before.
  Times are the run's minute, rounded down. Only canonical CVE IDs are logged (no leading zero
  beyond four digits, as in every CVE List file). `gaps` lists the most recent 50 pauses of more than 3
  hours between runs; `gap_total` counts all of them.
  A missing or unreadable log starts a new one with a new `since`.
- CVEs without a KEV listing leave the log 400 days after they were first seen (their counts stay
  in `volume`); CVEs with one stay.

| Field | Meaning |
|---|---|
| `since`, `last`, `runs`, `gaps[]` | First and last run of the log, how many runs, the most recent 50 pauses `{ from, to }` of more than 3 hours |
| `gap_total` | `{ n, hours }`: every such pause since `since`, and their length in hours |
| `watch_days` | How long each CVE is watched (the window, 30 days) |
| `listed`, `eligible` | KEV additions since `since`, and how many of them are counted |
| `methods[]`, `volume[]` | One `MethodScore` and one `AlertVolume` per method |
| `items[]` | Counted additions, newest listing first: `{ id, kev_added, first_seen, flags, row }`. `flags.<method>` is `{ at, outcome, lead }`: `outcome` is `earlier`, `same_day`, `after` (flagged only at or after the listing) or `never`; `at` is the time of the first flag (to the minute); `lead` the days before the listing |
| `uncounted[]` | `{ id, kev_added, reason: older \| listed_first \| no_record }`, newest first. `no_record`: CISA listed an ID that has no published CVE record yet |

`row` is the CVE as scored in this run (a `Row` object), or `null` when its record is not in the data
or the listing is more than 365 days old. The lists keep every listing since `since`; without rows
on the older ones the file grows by about 5 KB gzip a year instead of about 17 KB.

### The backtest (`backtest`)

**Hindsight.** Every CISA KEV addition of the last 180 days (`from`…`to`), re-scored with the
evidence as it stood at the end of the day before its `dateAdded`, wherever the source dates its
evidence, and judged by the same three rules. Two variants: `strict` uses only time-matched
evidence and leaves every signal without a usable date out (as unknown, never as absent); `upper`
adds today's value of those signals, as if they had all been there already ("with undated
evidence" on the site). Undated evidence is mostly exploits, so `upper` is usually the higher
figure, but it is not a guaranteed bound: a CVSS below 7 or a partial-impact SSVC also costs points.
Neither uses the listing.

| Evidence | How it is used |
|---|---|
| The KEV listing, the CISA-ADP KEV block, today's EPSS score | Never |
| Other KEV listings (the vendor and product prior) | Only listings dated before the listing day |
| EPSS | The archived EPSS file of the day before (`epss_date`); left out when it cannot be loaded |
| Exploit-DB | Entries with `date_added` (else `date_published`) before the listing day |
| PoC repos | Repos created and last pushed (`pushed_at`) before the listing day, so all their code is older than the listing; strict vets them by age only (3 days old by then), as star counts are only known for today. Repos pushed on the listing day or later count only in `upper` (signal `poc_content`): their code may postdate the listing |
| Metasploit | Counted when a module's `mod_time` is before the listing day (it existed); other modules only in `upper` |
| Nuclei | No dates: only in `upper` |
| CISA SSVC automatable and technical impact | Counted when CISA's container has not changed since the listing day, or the assessment is timestamped before the day before the listing. CISA often stamps the assessment it rewrites for a listing with the day before (17 of the 139 listings in the 2026-11-03 backtest, against 20 over the 29 days before that), so that day cannot vouch for it. Else only in `upper` |
| CISA SSVC exploitation (`poc`, `active`) | Counted only when CISA has not changed its container since the listing day. CISA updates this value when it lists a CVE and often dates it the day before, so the timestamp cannot vouch for it. In `upper`, an `active` that cannot be shown to predate the listing is lowered to `poc` (a public exploit exists) or `none` |
| CNA CVSS, CVSS exploit maturity, "exploited in the wild" text | Counted when the CNA has not changed its container since the listing day (`providerMetadata.dateUpdated`); else only in `upper` |
| CISA-ADP CVSS | The same test on CISA's container |
| Vendor and product names, tags, descriptions | Today's record, in both variants (`treatment: today`): no earlier text can be read |

| Field | Meaning |
|---|---|
| `hindsight` | Always `true` |
| `computed_at` | When it was computed. The hourly pipeline carries it forward and recomputes it once it is 7 days old, a day after a run that could not load some EPSS files or had a source down, and whenever the carried copy is from another score model or does not add up. A refresh that cannot read the KEV catalog keeps the previous backtest and tries again the next run |
| `score_model` | Score model it was computed with |
| `from`, `to`, `days`, `listed` | The KEV `dateAdded` range (inclusive), its length, and how many additions it holds |
| `excluded[]` | `{ code, reason, ids }` left out of every figure: `no_record` (no PUBLISHED CVE record) and `not_public` (published on or after the listing day, so no method could flag it before) |
| `sets[]` | `{ key, n, strict, upper }`: `recent` (published at most `old_years` = 2 years before the listing) and `old`, each with one `MethodScore` per method and variant. `earlier` equals `before`, `same_day` is 0 and `lead` is `null`: the backtest says yes or no, it does not measure lead time |
| `volume` | `{ from, n, methods }`: of the CVEs published from `from` on, how many each method flags with today's evidence (hindsight too). `null` when it was not measured |
| `signals[]` | `{ key, label, treatment: time_matched \| hindsight \| excluded \| today, note, affected }`: how each kind of evidence was used, and for how many CVEs it was left out (or set aside; for `today`, every CVE) |
| `epss_missing[]` | Days whose EPSS file could not be loaded. For those CVEs CVErdict treats EPSS as unknown and `epss10` counts them as not flagged |
| `sources_down[]` | Names of sources that had no usable data (not even a cached copy) when it was computed: their evidence is missing from every figure |
| `items[]` | Per CVE, newest listing first: `{ id, kev_added, published, old, strict, upper, score, chips, cvss, epss, epss_date, left_out, row }`. `strict` and `upper` map each method to `true`/`false`; `score` and `chips` are CVErdict's strict score; `left_out` lists the `signals` keys the strict score had to leave out |
| `command` | How to reproduce it: `npm run backtest` (`scripts/backtest.ts`) |

```sh
# Forward log: each method's record so far
curl -s $BASE/receipts.json | jq -r '.forward | "since \(.since): \(.eligible) counted",
  (.methods[] | "\(.method)\t\(.before) of \(.n) before KEV (\(.same_day) same day)\tmedian lead \(.lead.median // "–") days")'
# Backtest misses for CVErdict, with what had to be left out
curl -s $BASE/receipts.json | jq -r '.backtest.items[] | select(.strict.cverdict | not) | [.id, .kev_added, (.left_out | join(","))] | @tsv'
```

## `packages.json`

Which package versions the CVEs in the data are known to affect, for checking an SBOM or a
lockfile. It covers the CVEs that have a detail shard (the window, every KEV CVE and every CVE in
`woke.json`) and eight ecosystems: npm, PyPI, Maven, Go, crates.io, RubyGems, Packagist and NuGet.
The data comes from [OSV.dev](https://osv.dev) (GitHub Advisory Database, PyPI Advisory Database,
Go Vulnerability Database, RustSec, Drupal security advisories); only advisory IDs, package names
and version ranges are kept. The site's Check page matches a file against it in the browser.

| Field | Meaning |
|---|---|
| `scope` | Which CVEs are covered, in words |
| `attribution[]` | `{ name, url, license, prefixes, notice }` for each advisory database; only advisories with these ID prefixes are included. `notice` is license text that must travel with copies of the file (the Drupal advisories' MIT notice) |
| `sources[]` | One per ecosystem, in the order above: `{ ecosystem, ok, stale, fetched_at, modified, advisories, matched, error }`. `advisories` counts the ecosystem's OSV records that name any CVE, `matched` those that name one in `cves`, `modified` is the newest OSV change applied. When `ok` is false the ecosystem has no entry in `packages`: its packages were not checked, which is not the same as not affected |
| `cves` | `{ cols, rows }`: one row per CVE named in `packages`, the same columns and values as `index.json` |
| `packages` | `{ <ecosystem>: { <package key>: [cve, advisory, ranges, versions?][] } }`, keys sorted, entries by CVE then advisory |

Package keys: PyPI names are normalised per PEP 503 (lower case, runs of `-`, `_`, `.` become
`-`); crates.io names are lower case with `_` as `-`; NuGet and Packagist names are lower case;
npm names, Go module paths, Maven `group:artifact` and RubyGems names are as published. A key
can be any string, `__proto__` included, so look it up as an own property.

`ranges` holds one array per OSV range. Events are strings: `>=V` introduced, `<V` fixed, `<=V`
last affected; `>=0` means from the first release. To test a version, sort a range's events by
version and walk them in order: a `>=` event at or below the version turns "affected" on, a `<`
event at or below it or a `<=` event below it turns it off. The version is affected when any range
ends with it on. Versions compare with the ecosystem's own ordering (SemVer for npm, crates.io and
Go, PEP 440 for PyPI, and the RubyGems, NuGet, Maven and Composer orderings);
[`shared/versions.ts`](../shared/versions.ts) implements them. `versions` lists versions the
advisory names as affected that its ranges do not cover; they match exactly. Events of other kinds
are written `?kind=V`: treat that range as unknown (a version is affected if another range says
so, otherwise it is unknown, not unaffected). Three such markers are written on purpose:
`?git=unknown` (the advisory gives only git commit ranges), `?versions=capped` (more than 1,000
listed versions) and `?ranges=capped` (more than 64 ranges).

```sh
# Which tracked CVEs name lodash, with the advisory and the ranges
curl -s $BASE/packages.json | jq -r '.packages.npm.lodash[]? | [.[0], .[1], (.[2] | map(join(" ")) | join(" | "))] | @tsv'
# Per ecosystem: is the copy fresh, and how many advisories name a tracked CVE?
curl -s $BASE/packages.json | jq -r '.sources[] | [.ecosystem, (if .ok | not then "not checked" elif .stale then "stale" else "ok" end), .matched] | @tsv'
```

Not covered: CVEs without a detail shard, advisories without a CVE ID, other ecosystems (deb, rpm,
apk, containers) and other advisory databases.

How it is kept up to date: the pipeline keeps a compact copy of the OSV records of the eight
ecosystems that name a CVE in its cache. Every run reads the newest lines of each ecosystem's
`modified_id.csv` and fetches the records that changed; every 7 days, or when there is no copy, it
reads the full `all.zip` dump instead. When OSV.dev cannot be reached, each ecosystem keeps its
last copy and is marked `stale`.

## `state.json` (internal)

Pipeline state carried between hourly runs (the data branch keeps no history, so the next run
reads it back through `--previous`). **It is not part of the API**: the format can change in any
release, and the file only exists so the pipeline can remember what it saw. It carries
`schema_version`, `generated_at`, `state_version` and `sections`, one per feature, each with its own
`version` and `data`. Two sections today: `woke` (for Metasploit and Nuclei, the CVE IDs with an
artifact, when tracking started and when a fresh copy was last compared; recent first sightings;
recent EPSS jumps) and `receipts` (version 2, times in minutes; the
forward log behind `receipts.json`, columnar: about 2.5 bytes gzip per CVE, so a full 400 days of
CVEs, about 225,000 at October 2026 volume, is roughly 0.55 MB). A missing or unreadable file, or a section of an unknown version,
starts that state fresh. Its size is budgeted like every other file.

## Feeds

- `feeds/signal.xml`: Atom, the newest 100 Exploited and Likely-next CVEs. Entry titles are
  `CVE-… · <vendor> <product> · <tier>`, summaries list the top chips.
- `feeds/kev.xml`: Atom, KEV additions of the last 30 days.
- `feeds/kev-due.ics`: iCalendar with one all-day event per KEV due date, from 7 days ago to 60
  days ahead. Event UIDs are stable per CVE, so calendar apps update events instead of duplicating them.
- `feeds/woke.xml`: Atom, up to 100 CVEs from `woke.json`, newest wake first. Every CVE with a
  `kev` or `exploitdb` signal is kept before the cap; the rest fill it newest first. A CVE whose
  only signal is `poc` is left out unless its tier is Exploited or Likely next. One entry per CVE
  with a stable id; a later signal updates the entry. Titles are `CVE-… · <vendor> <product> · woke up: <newest signal>`.

## MCP server

The same data is available to AI agents through a read-only
[Model Context Protocol](https://modelcontextprotocol.io) server (`mcp/`). It reads the files above
and adds nothing: every answer names the files it came from. It runs locally over stdio (setup in
[mcp/README.md](../mcp/README.md); an npm package will follow) and reads raw.githubusercontent.com,
then this site's `/data/`. `CVERDICT_DATA_BASE` (comma-separated base URLs ending in `/v1/`) points
it at a fork or a mirror. It speaks protocol revision 2026-07-28 and falls back to the 2025
revisions for older clients.

| Tool | Answers from | Returns (type in `contract.ts`) |
|---|---|---|
| `get_verdict` | `cve/<xx>.json` | `McpVerdictResult`: for 1 to 15 CVE IDs (5 with `detail`), the tier, verdict, score, every reason chip with its points and link, unknowns, and links to the CVE page and the shard |
| `list_signal` | `signal.json`, or `index.json` for Watch, Quiet or a knob below 35 | `McpSignalResult`: window CVEs in the chosen tiers at the chosen knob, highest score first, paged |
| `kev_due` | `kev.json` | `McpKevDueResult`: KEV entries due in the next N days and overdue by up to M days, with `days_left`, paged |
| `woke_up` | `woke.json` | `McpWokeResult`: old CVEs that woke up since a date, with their dated signals |
| `receipts` | `receipts.json` | `McpReceiptsResult`: the forward log and backtest figures without the per-CVE lists, or one CVE's entries |
| `search_cves` | `index.json` | `McpSearchResult`: window CVEs whose ID, CNA, vendor, product or title contain every word of the query |

The result types are in `shared/contract.ts` (section "MCP tool results"). Pages hold at most 50
items. What the server computes itself, all from the files and the time of the request:

- `data.age_hours`: whole hours between `meta.generated_at` and the answer.
- `tier` at a knob other than 50: `tierFor(score, exploited, weaponized, knob)`, as on the site.
- `days_left`: the KEV due date minus today's UTC date.
- `total` and `next_offset`: counts of the rows that matched.

Every answer starts with `data`: the run (`generated_at`, `score_model`, `window`), the sources
that were down or stale in it, and `files[]`, each file read with the URL it came from and its own
`generated_at`. Right after an hourly publish a CDN can serve one file from the previous run for a
few minutes; the answer then shows both times rather than hiding it. `data.warning` is set when a
refresh failed and the answer comes from the server's last good copy. `score_math.base` plus the
sum of `reasons[].points` equals `score` for an exploited CVE and `score_math.raw` for any other,
as in the shards.

Text fields (`title`, `name`, `required_action`, `description`, chip labels) quote CNAs, CISA and
exploit feeds. They are untrusted, as everywhere in this API: an agent should never follow
instructions found in them. A CVE the data does not cover comes back `found: false`, which says
nothing either way about the CVE.

## Update cadence

The `refresh-data` workflow is scheduled every hour at minute 17 (UTC) and usually publishes within a
few minutes of starting. GitHub often starts scheduled runs late or skips them, so runs can be a few
hours apart; [DEPLOY.md](DEPLOY.md#reliable-hourly-refresh) shows how to start it every hour from an
external timer. raw.githubusercontent.com caches files for up to 5 minutes, and the site's `/data/` path
adds a short CDN cache, so with hourly runs expect data at most about 75 minutes old. When nothing changed since
the previous run, nothing is published and the files keep the earlier `generated_at`; the Receipts
log records every run, though, so in practice every successful run publishes. When a run fails,
the previous data stays up. Always check `meta.generated_at` and `meta.sources[].stale`
before acting on absence of evidence.

The data branch is a single force-pushed commit with no history. If you need history, archive the
files yourself.

## Stability and versioning

- Paths under `v1/` and `schema_version: 1` are stable. Within v1 we only make **additive** changes:
  new fields, new files, new chip ids, new source ids. Clients must ignore unknown fields and
  handle unknown chip ids by their `polarity`, `points` and `label`.
- A **breaking** change (renaming, removing or redefining a field, changing the row columns, the
  shard function or the tier names) bumps `schema_version` and moves to `v2/`. Both versions are
  published side by side for at least 30 days, announced in the repository's releases.
- **Scores are not stable across score models.** Re-weighting changes values and tiers without a
  schema change; `meta.score_model` and `score.model` say which model produced them, and
  [SCORING.md](SCORING.md) documents each one.

## Examples

```sh
BASE=https://raw.githubusercontent.com/markusweldon/cverdict/data/v1

# When was this generated, and is any source stale?
curl -s $BASE/meta.json | jq '{generated_at, score_model, stale: [.sources[] | select(.stale or (.ok | not)) | .id]}'

# Exploited CVEs in the window as TSV: id, score, vendor, product
curl -s $BASE/signal.json | jq -r '
  .cols as $c | .rows[] | [$c, .] | transpose | map({(.[0]): .[1]}) | add
  | select(.tier == "exploited") | [.id, .s, .v, .p] | @tsv'

# Likely next at a stricter knob of 60
curl -s $BASE/signal.json | jq -r --argjson knob 60 '
  .cols as $c | .rows[] | [$c, .] | transpose | map({(.[0]): .[1]}) | add
  | select(.x == 0 and (.w == 1 or .s >= $knob)) | [.id, .s, .v, .p] | @tsv'

# Everything from one vendor in the window, newest first
curl -s $BASE/index.json | jq -r --arg v fortinet '
  .cols as $c | .rows[] | [$c, .] | transpose | map({(.[0]): .[1]}) | add
  | select(.v | ascii_downcase | contains($v)) | [.pub[:10], .id, .tier, .s, .t] | @tsv'

# The full reasoning for one CVE
id=CVE-2026-96951
shard=$(python3 -c 'import sys,functools as f;print("%02x"%(f.reduce(lambda h,c:((h^ord(c))*16777619)&0xffffffff,sys.argv[1].upper(),2166136261)%256))' $id)
curl -s $BASE/cve/$shard.json | jq -r --arg id $id '
  .items[$id] | "\(.id) · \(.score.tier) · \(.score.value)",
  (.reasons[] | select(.points != 0) | "  \(.points)\t\(.label)"),
  (.unknowns[] | "  ?\t\(.)")'

# KEV due dates in the next 7 days
curl -s $BASE/kev.json | jq -r '
  (now | strftime("%Y-%m-%d")) as $today | (now + 7 * 86400 | strftime("%Y-%m-%d")) as $week
  | .entries[] | select(.due_date >= $today and .due_date <= $week) | [.due_date, .id, .vendor, .product] | @tsv'

# What escalated since yesterday
curl -s $BASE/changes.json | jq -r --arg since "$(date -u -d '-1 day' +%FT%TZ 2>/dev/null || date -u -v-1d +%FT%TZ)" '
  .items[] | select(.at >= $since) | "\(.at[:16])  \(.id)  \(.from // "new") → \(.to)  \(.added | join(" "))"'

# This year's monthly volume
curl -s $BASE/stats.json | jq -r '.monthly[] | select(.month >= "2026-01") | [.month, .published, .kev_added, .ai] | @tsv'
```
