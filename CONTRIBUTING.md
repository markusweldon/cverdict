# Contributing to CVErdict

Thanks for helping. Bug reports, score disputes, new data sources and code are all welcome. By
taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go through
[private reporting](SECURITY.md), never a public issue.

## Development setup

You need Node **22.12+**, git, and about 1 GB of disk for the CVE List clone. `jq` is only needed to
run `scripts/publish-data-branch.sh` locally.

```sh
git clone --single-branch https://github.com/markusweldon/cverdict.git
cd cverdict
npm ci
npm run mock                   # deterministic mock data in site/public/data, for site work
npm run pipeline               # or real data (the first run clones cvelistV5: a few minutes)
npm run dev                    # http://localhost:5173
```

| Command | What it does |
|---|---|
| `npm run pipeline -- [flags]` | Build the data tree (`--help` lists every flag) |
| `npm run mock -- [dir]` | Write a deterministic mock data tree (default `site/public/data`) |
| `npm run calibrate -- [flags]` | Print the calibration report for the current score model (`--help` lists the flags) |
| `npm run backtest -- [flags]` | Print the hindsight backtest behind the Receipts page (`--help` lists the flags) |
| `npm run dev` | Vite dev server for the site, serving `site/public/data` |
| `npm run build` | Production build into `site/dist` (`BASE=/repo/` for a sub-path) |
| `npm run preview` | Serve the production build |
| `npm test` | All unit tests (vitest) |
| `npm run typecheck` | `tsc --noEmit` over shared, pipeline, site, mcp, api and scripts |
| `npm run -s mcp` | The MCP server over stdio, from source ([mcp/README.md](mcp/README.md)); `-s` keeps npm's banner off stdout |
| `npm run build:mcp` | The MCP server as one file, `mcp/dist/cverdict-mcp.mjs` |

Pipeline flags that make iteration fast:

- `--offline` replays the last downloads from `.cache/` without touching the network.
- `--now 2026-10-26T19:30:00Z` freezes time, so two runs are comparable.
- `--cvelist-dir <clone>` and `--poc-dir <clone>` reuse existing git clones (they are never modified).
- `--window-days 7` shrinks the window for quick experiments; `--knob 60` changes the default knob.

## Project layout

```text
shared/     contract.ts (public data types), model.ts (chips and points), shard.ts, brand.ts, cna.ts (CNA display
            names), verdict.ts and share.ts (verdict words and link-preview tags), share-images.ts (share image
            hashes), versions.ts and packages.ts (version ranges and package keys for the Check Deps page),
            mcp.ts (MCP snippets and tool copy)
api/        share.ts: the Vercel Function for link-preview bots (tests in api/_test/)
pipeline/   src/ (sources → normalize → score → batches/stats/changes → emit → validate), test/
site/       the Vite + Preact single-page app
mcp/        the read-only MCP server for AI agents: src/, test/, the cverdict-mcp package files
docs/       SPEC.md (build spec), SCORING.md, DATA.md, DEPLOY.md
.github/    ci.yml, refresh.yml (hourly data), release-mcp.yml (npm releases of mcp/), issue templates
scripts/    publish-data-branch.sh, mock-data.ts, validate-data.ts, calibrate.ts, backtest.ts, mcp-measure.ts
tools/og/   render.mjs: renders the share images in site/public/og/ (own lockfile, run by hand)
```

[docs/SPEC.md](docs/SPEC.md) is the implementation contract; read it before larger changes.

## Ground rules for code

- TypeScript, strict, ESM. The only runtime dependency is `preact`; the pipeline and the function in
  `api/` use Node built-ins only. The MCP server's SDK and `zod` are exact-pinned dev dependencies that
  its bundle inlines; only `mcp/` imports them. Propose a new dependency in an issue first.
- `api/share.ts` runs as plain Node ESM, so it and every file of `shared/` it imports use `.js`
  extensions on relative imports; `npx tsc -p api/tsconfig.json` checks that, as CI does.
- **CVE text is hostile.** Render it as text only: no `innerHTML`, no `dangerouslySetInnerHTML`.
  Only link `http(s)` URLs, with `rel="noopener noreferrer nofollow"`. Escape everything that goes
  into XML or iCalendar.
- Brand strings come from `shared/brand.ts`; documentation and templates use the placeholders
  `CVErdict` and `cverdict`.
- Changing anything in `shared/contract.ts` changes the public API: follow the
  [versioning policy](docs/DATA.md#stability-and-versioning).
- Fail soft: a source being down must never break a run.

## Tests

Tests live in `pipeline/test/` and `mcp/test/`, next to the code in `shared/` and `site/src/` as
`*.test.ts`, and in `api/_test/` (every other file in `api/` becomes a Vercel Function). They run with vitest:

```sh
npm test                                   # everything
npx vitest run pipeline/test/model/score.test.ts
```

Every chip and every family rule must have a unit test. Fixtures in `pipeline/test/fixtures/` are small,
realistic CVE records, including ones with XSS payloads; add one whenever you fix a parsing bug.
On every pull request, CI runs `npm run typecheck`, `npm test`, `npm run build` and `npm run build:mcp`.
It also checks the link-preview function as Node ESM and the share block in the built page,
smoke-tests the MCP bundle on mock data, checks the mock data with `scripts/validate-data.ts`, runs
`shellcheck`, tests the data-branch publisher and checks that `vercel.json` is valid JSON.
A change to the MCP tools' output should also pass `npx tsx scripts/mcp-measure.ts`, which checks
the largest possible answers on the live data against the 20,000-token budget.

## Proposing a scoring change

Scores only earn trust if changes to them are measured. A pull request that changes a weight in
`shared/model.ts` or a firing rule in `pipeline/src/score.ts` must:

1. Bump `SCORE_MODEL` and update the unit tests and [docs/SCORING.md](docs/SCORING.md).
2. Include a **calibration diff**: run `npm run calibrate -- --offline --now <same instant>` on the
   same frozen inputs before and after the change and paste both reports. The report has:
   - tier counts and pass rate of every window CVE at knobs 40, 45, 50, 55 and 60;
   - recall of the current year's KEV additions without the answer key. Each addition is re-scored
     on its own: its KEV entry and the CISA-ADP KEV block removed, SSVC *active* lowered to *poc*
     (when a public exploit artifact exists) or *none*, and its EPSS score dropped. The KEV prior
     stays the one built from the full catalogue, minus the CVE itself, as in a normal run. Do not
     empty the whole catalogue instead: that turns every prior into `prior.none`;
   - the tiers of the largest patch-day batch (`--batch <id>` picks another).

   Add the 20 CVEs whose tier moved the most, with their chips before and after (compare two
   `npm run pipeline -- --offline --now <same instant>` outputs).
3. Say what the change makes worse, not only what it improves, and how it avoids look-ahead bias
   (evidence that tends to appear only after exploitation is already known).

Small disputes about one CVE are better as a
["Disagree with a score"](https://github.com/markusweldon/cverdict/issues/new?template=disagree-with-a-score.yml)
issue. The site's "Disagree?" button prefills it through the form's field ids, which are therefore
stable:

```text
https://github.com/markusweldon/cverdict/issues/new?template=disagree-with-a-score.yml&title=Score%3A+CVE-2026-12345&cve=CVE-2026-12345&tier=likely&score=62&model=v0.1.0
```

## Adding a data source

Open a ["Propose a data source"](https://github.com/markusweldon/cverdict/issues/new?template=new-data-source.yml)
issue first. A source is accepted when it passes this checklist:

- [ ] **License**: free to download without an account or API key, and the license allows
      republishing data derived from it. Add it to [ATTRIBUTIONS.md](ATTRIBUTIONS.md) with any
      required notice, and to the sources table in the README.
- [ ] **Signal**: it adds evidence we do not have, measured on real data (how many window CVEs it
      touches, and how much earlier than KEV), and it maps to a chip in an existing family or a
      justified new one in `shared/model.ts`.
- [ ] **Cadence**: how often it updates and how often we may fetch it (respect rate limits; reuse
      the cache when the upstream asks for it, as Exploit-DB does).
- [ ] **Fallback**: a mirror if one exists, then the last good cached copy; the run carries on and
      the source is reported as stale in `meta.sources`.
- [ ] **Sanity check**: a minimum record count (or similar) in `pipeline/src/config.ts`, so a
      truncated or empty download is rejected instead of wiping out evidence.
- [ ] **Untrusted input**: parsed defensively, text sanitised, nothing executed, no HTML kept.
- [ ] **Budgets**: published files stay within the size budgets checked by `validate.ts`.
- [ ] **Docs and tests**: a fixture and parser tests, a `SourceStatus` id in `shared/contract.ts`,
      and the new fields in [docs/DATA.md](docs/DATA.md).

## Pull requests

- Keep them focused; one change per pull request.
- Explain what changed and why, and link the issue.
- Make sure `npm run typecheck`, `npm test` and `npm run build` pass locally.
- Contributions are licensed under the project's [MIT license](LICENSE); data contributions that
  end up in published scores are CC0.
