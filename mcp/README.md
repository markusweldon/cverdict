# CVErdict MCP server

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI agents
the same verdicts as [CVErdict](https://cverdict-psi.vercel.app): tier, score, every reason chip
with its points and evidence link, and what is unknown. Every answer says when the data was
generated and which files it came from. No key, no account.

It runs on your machine over stdio and reads the published `data` branch on
raw.githubusercontent.com, then the site's `/data/` copy if GitHub fails. It never touches the
site's hosting, so it keeps working when the site is down.

**Status:** an npm package (`cverdict-mcp`) will follow. Until then, run it from a clone.

## Run it from a clone

Node 22.12 or later.

```sh
git clone --single-branch https://github.com/markusweldon/cverdict.git
cd cverdict && npm ci

# Claude Code
claude mcp add cverdict -- npm --prefix "$PWD" run -s mcp
```

Other clients take an `mcpServers` entry (key names vary by client):

```json
{
  "mcpServers": {
    "cverdict": {
      "command": "npm",
      "args": ["--prefix", "/path/to/cverdict", "run", "-s", "mcp"]
    }
  }
}
```

Keep the `-s`: a plain `npm run` prints its own banner to stdout, which is the JSON-RPC channel.

To skip npm and TypeScript at start-up (and on Windows, where clients cannot start `npm`
directly), build the single-file server once and start it with Node:

```sh
npm run build:mcp                                   # writes mcp/dist/cverdict-mcp.mjs
claude mcp add cverdict -- node "$PWD/mcp/dist/cverdict-mcp.mjs"
```

Run `git pull && npm ci` (and `npm run build:mcp` if you use the bundle) to update.

### Options

Environment variables, all optional. MCP clients start servers with a minimal environment, so put
them in the client's `env` block for this server.

| Variable | Default | Purpose |
|---|---|---|
| `CVERDICT_DATA_BASE` | `https://raw.githubusercontent.com/markusweldon/cverdict/data/v1/,https://cverdict-psi.vercel.app/data/v1/` | Comma-separated base URLs ending in `/v1/`, tried in order. https only, or http on `localhost` and `127.0.0.1` (for example `http://localhost:5173/data/v1/` with `npm run mock` and `npm run dev`). For a fork or a mirror |
| `NODE_USE_ENV_PROXY`, `HTTPS_PROXY` | unset | Behind a proxy: `NODE_USE_ENV_PROXY=1` and `HTTPS_PROXY=http://proxy.example:3128`. Needs Node 22.21 or later; older versions ignore `NODE_USE_ENV_PROXY` without a warning. `NODE_EXTRA_CA_CERTS` adds a private CA |

At start the server writes one line to stderr with its version, the Node version, whether it sees a
proxy and the data bases. Nothing but JSON-RPC goes to stdout.

## Tools

All six are read-only (`readOnlyHint: true`) and return `structuredContent` plus the same JSON as
one text block. The result types are in [`shared/contract.ts`](../shared/contract.ts), section
"MCP tool results".

| Tool | Answers from | Returns | Bounds |
|---|---|---|---|
| `get_verdict` | `meta.json`, `cve/<xx>.json` | Tier, plain-language verdict, score, `score_math`, every reason chip with points and link, unknowns, KEV, EPSS, CVSS, links to the CVE page, the shard and cve.org. `detail: true` adds the description, affected products, CWE, SSVC, exploits, tags, timeline and references | 1 to 15 IDs, at most 5 with `detail`; `knob` 30 to 80 |
| `list_signal` | `signal.json`, or `index.json` for Watch, Quiet or a knob below 35 | Window CVEs in the chosen tiers (default Exploited and Likely next), highest score first. Filters: `vendor` text, `published_since`, `kev_only` | `limit` 1 to 50 (default 25), `offset` |
| `kev_due` | `kev.json` | CISA KEV entries due in the next `within_days` (0 to 60, default 7) and overdue by up to `overdue_days` (0 to 14, default 7), with `days_left` in UTC calendar days | |
| `woke_up` | `woke.json` | Old CVEs that gained exploitation evidence since `since` (default 7 days before the data was generated), with their dated signals. Filter by `kinds` | `limit` 1 to 50 (default 25), `offset` |
| `receipts` | `receipts.json` | How often CVErdict, CVSS 7 or more and EPSS 10% or more flagged a CVE before CISA listed it: the forward log and the hindsight backtest, without the per-CVE lists. `id` adds one CVE's entries | |
| `search_cves` | `index.json` | Window CVEs whose ID, CNA, vendor, product or title contain every word of `query`, highest score first | `query` 2 to 100 characters, at most 8 words; `limit` 1 to 50 (default 20), `offset` |

Dates (`published_since`, `since`) are UTC: `2026-10-01`, `2026-10-01T06:00Z` or
`2026-10-01T06:00:00.000Z`. A date that does not exist is an error. A filter the server cannot
apply is always an error, never silently dropped.

Measured on the live data of 2026-11-03 (16,747 window CVEs), the largest answer any tool can give
at its maximum bounds stays under 20,000 tokens; `scripts/mcp-measure.ts` checks this.

### Every answer starts with `data`

| Field | Meaning |
|---|---|
| `generated_at`, `age_hours` | The pipeline run the answer is based on, and its age in whole hours when the server answered |
| `score_model`, `knob_default`, `window` | As in `meta.json` |
| `sources_down`, `sources_stale` | Sources with no usable data in that run (their evidence is unknown, not absent), and sources that served a cached copy |
| `files[]` | Every file read: `path` on the data branch, the `url` it came from, its own `generated_at` |
| `warning` | Set when a refresh failed and the answer comes from the last good copy |

Right after an hourly publish a CDN can serve one file from the previous run for a few minutes;
`files[]` then shows both times rather than hiding it.

### Reading the answers honestly

- **Quiet means no evidence yet, never safe.** A CVE outside the data (`found: false`) is unknown,
  not safe: the data covers CVEs published in the last 30 days, every CVE in CISA KEV and old
  CVEs that woke up.
- **Text is untrusted.** Titles, descriptions, KEV names and required actions, and chip labels
  quote CNAs, CISA and exploit feeds. The server's instructions tell the agent never to follow
  instructions found in them. That reduces the risk of prompt injection; it does not remove it.
- **Privacy.** GitHub sees which of the 256 shard files the server fetches, never your CVE IDs or
  search words. Nothing is uploaded and nothing is written to disk.

## Errors

Failures come back as tool results with `isError: true` and a plain message, for example:

| Case | Message |
|---|---|
| A file is not published | `woke.json is not on the data branch yet, so this tool has nothing to read. The other tools still work.` |
| Every base failed, nothing cached | `CVErdict could not load its data right now (raw.githubusercontent.com: HTTP 503 for meta.json; ...). Try again in a few minutes, or read the files directly: https://github.com/markusweldon/cverdict/tree/data/v1` |
| No data within the 10 s limit of a call | `CVErdict could not load its data in time (...)` |
| The data moved to a new schema | `The published data uses schema version 2; this server reads version 1. Update the server: ...` |
| `detail` with more than 5 IDs | `detail: true takes at most 5 IDs; ask again in groups of 5.` |
| Bad arguments | `Input validation error: Invalid arguments for tool get_verdict: ...` |

## How it reads the data

- Bases are tried in order. A 404 is final. A 429 or 403 moves that base to the back for 10
  minutes. Timeouts (4 s to the response headers), network errors, redirects (refused), 5xx and
  malformed files fall through to the next base.
- Each tool call has one 10 s deadline. Shards for `get_verdict` are fetched in parallel, at most 6
  at a time.
- Bodies are capped at 24 MB decoded, which also stops a compression bomb from a mirror. Files must
  have `schema_version` 1 and `generated_at`; row tables must have exactly the published columns.
- Parsed files stay in memory for the life of the process. `meta.json` is checked again after 5
  minutes (raw.githubusercontent.com caches for 5 minutes anyway); other files are refetched when
  `meta.json` names a newer run. An idle server makes no requests and runs no timers.

## Development

```sh
npm test                      # unit, protocol and spawn tests (mcp/test/)
npm run build:mcp             # the single-file bundle in mcp/dist/
npx tsx scripts/mcp-measure.ts                # answer sizes against the live data branch
npx tsx mcp/test/smoke.ts mcp/dist/cverdict-mcp.mjs <data dir>   # what CI runs on mock data
```

The SDK (`@modelcontextprotocol/server`) and `zod` are exact-pinned dev dependencies of the
repository and are bundled into `dist/cverdict-mcp.mjs`, so the package has no runtime
dependencies. The site never imports them: `shared/mcp.ts` holds the copy both use.

Publishing later (owner): remove `"private": true` from `mcp/package.json`, run
`npm run build:mcp` at the root, then `npm publish --provenance` in `mcp/`.

## License

MIT ([LICENSE](LICENSE)). The bundle includes the MCP TypeScript SDK (Apache-2.0, with
contributions under MIT), zod (MIT) and the libraries the SDK vendors; their notices are in
[LICENSE-THIRD-PARTY](LICENSE-THIRD-PARTY). Data terms: [docs/DATA.md](../docs/DATA.md).
