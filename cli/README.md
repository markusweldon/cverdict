# cverdict-check

Which of your dependencies' CVEs are **exploited** or **likely next**, today.

`cverdict-check` reads your lockfiles and SBOMs, matches them against the CVEs
[CVErdict](https://cverdict.dev) tracks, and sorts the hits by its verdicts: Exploited, Likely next, Watch and
Quiet. It uses the same parser and matcher as the site's [Check Deps](https://cverdict.dev/check) page. Your files
are read where the check runs; the only download is the public index, `packages.json` (under 1 MB).

It checks every CVE that an [OSV.dev](https://osv.dev/) advisory ties to a package version, about 47,000
advisories, and ranks the hits by exploitation evidence, so the few to fix first come first. Most old CVEs land in
Quiet; one with a Metasploit module or a Nuclei template is Likely next at any age. Not covered: advisories without
a CVE ID (malware reports among them), OS packages and containers (deb, rpm, apk) and bugs no advisory names yet.
"Affected" means the version is inside an advisory's range, not that your code reaches the vulnerable part.

## On your machine

```sh
npx -y cverdict-check                 # this folder and below
npx -y cverdict-check package-lock.json api/poetry.lock sbom.cdx.json
npx -y cverdict-check --fail-on likely --format json -o cverdict.json
```

```text
CVErdict check
Checked 3 packages in 1 file against the <n> CVEs OSV.dev advisories tie to package versions (data of 2026-11-26 17:47 UTC, evidence bar 50).

EXPLOITED (1)
  CVE-2025-54313  score 97  KEV due 2026-02-12  prettier · eslint-config-prettier
    @pkgr/core 0.2.8  fixed in 0.2.9  package-lock.json:7

LIKELY NEXT (1)
  CVE-2026-112947  score 18  vitejs · vite
    vite 8.3.1  fixed in 8.3.3  package-lock.json:10

Result: fail. 1 CVE at Exploited (--fail-on exploited).
```

Files read: CycloneDX (JSON, XML), SPDX (JSON, tag-value), package URL lists, and the lockfiles of npm
(`package-lock.json`, `npm-shrinkwrap.json`), yarn, pnpm, pip (`requirements*.txt`), Poetry, uv, Pipenv, Go
(`go.mod`, or `go.sum` without a `go.mod` beside it), Cargo, Bundler, Composer, NuGet (`packages.lock.json`)
and Gradle (`*.lockfile`). Folders are searched for those names and for `bom.json`, `bom.xml`, `sbom*.json`,
`*.cdx.json`, `*.cdx.xml`, `*.spdx` and `*.spdx.json`. `node_modules`, `vendor`, virtualenvs, build output and
VCS folders are skipped, and symbolic links are not followed.

| Option | |
|---|---|
| `--fail-on <tier>` | Exit 1 when a confirmed CVE is at this tier or above: `exploited` (default), `likely`, `watch`, `quiet` or `never` |
| `--evidence-bar <n>` | The score a CVE needs for Likely next (default 50, as on the site) |
| `--format <f>` | `text` (default), `markdown`, `json` or `sarif` |
| `-o, --output <file>` | Write the report to a file instead of stdout |
| `--sarif <file>` | Also write SARIF 2.1.0 |
| `--summary <file>` | Also append the Markdown report (for `$GITHUB_STEP_SUMMARY`) |
| `--annotations` | Print GitHub workflow annotations |
| `--data <url\|path>` | Read `packages.json` from a mirror, a data folder or a file |

Exit codes: **0** passed, **1** a confirmed CVE at or above `--fail-on`, **2** the check could not run (no files
found, the index could not be loaded, or no file could be read).

"Possibly affected" CVEs (the version in your file could not be compared, or is not exact) are listed but never
fail a run.

## In GitHub Actions

```yaml
# .github/workflows/cverdict.yml
name: cverdict
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '17 6 * * *' # verdicts change after you merge: re-check every day
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: markusweldon/cverdict/action@check-v0.1.0
        with:
          fail-on: exploited
```

The scheduled run is the point: a dependency you shipped last month can turn Exploited today, and Dependabot
does not rank alerts by exploitation evidence. The step writes a job summary and annotates the lockfile lines.

To see the findings in the repository's **Security → Code scanning** tab, write SARIF and upload it:

```yaml
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: markusweldon/cverdict/action@check-v0.1.0
        id: cverdict
        with:
          fail-on: never
          sarif-file: cverdict.sarif
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: cverdict.sarif
          category: cverdict
```

Exploited CVEs show as critical alerts, Likely next as high and Watch as medium (SARIF `security-severity` 9.5,
8.0 and 5.0); Quiet and possibly affected ones are left out of SARIF and annotations.

| Input | Default | |
|---|---|---|
| `path` | `.` | Lockfiles, SBOMs or folders, one per line |
| `fail-on` | `exploited` | `exploited`, `likely`, `watch`, `quiet` or `never` |
| `evidence-bar` | `50` | Score for Likely next |
| `sarif-file` | | Also write SARIF here |
| `summary` | `true` | Write the job summary |
| `annotations` | `true` | Annotate lockfile lines |
| `data-url` | | A mirror of the data, or a path in the workspace |

| Output | |
|---|---|
| `exploited`, `likely`, `watch`, `quiet`, `possible` | Distinct CVEs in each group |
| `failing-cves` | Distinct CVEs at or above `fail-on` |
| `failed` | `true` when the step failed |
| `sarif-file` | The SARIF file written, if any |

The Action needs no token and sends nothing anywhere: it reads the checkout and downloads the public index from
`raw.githubusercontent.com` (falling back to `cverdict.dev`). Behind a proxy, set `NODE_USE_ENV_PROXY: 1` with
`HTTPS_PROXY` in the step's `env` (the Action runs on Node 24, which reads them).

## Safety

Lockfiles, SBOMs and upstream CVE titles are untrusted text. Nothing from them is executed; the Markdown summary
escapes them (a job summary renders HTML), annotations escape the workflow-command syntax, and file names never
become shell arguments.

## Data and licenses

The code is MIT. The index is built from [OSV.dev](https://osv.dev/) advisories (GitHub Advisory Database, PyPA, Go
and RustSec, CC-BY-4.0 or CC0-1.0) joined with CVErdict's scores (CC0): see
[ATTRIBUTIONS.md](https://github.com/markusweldon/cverdict/blob/main/ATTRIBUTIONS.md).

## Developing and releasing

```sh
npm run check -- package-lock.json   # from source
npx vitest run cli/test
npm run build:cli                    # cli/dist/cverdict-check.mjs and action/dist/index.mjs
```

`action/dist/index.mjs` is committed, because a JavaScript action runs it as is. CI fails when it differs from a
fresh build: after changing `cli/src`, `shared` or `site/src/check`, run `npm run build:cli` and commit it.

To release, bump `version` in `cli/package.json` and `cli/src/version.ts`, merge, then push a tag
`check-v<version>`. [release-check.yml](../.github/workflows/release-check.yml) checks, packs and publishes to npm
with trusted publishing (set up once on npmjs.com: package `cverdict-check` → Settings → Trusted publishing →
GitHub Actions, this repository, workflow `release-check.yml`). Action users pin the same tag.
