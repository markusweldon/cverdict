#!/usr/bin/env bash
# Publish a pipeline output tree to the orphan data branch of this repository.
#
#   scripts/publish-data-branch.sh [--dry-run] <dir>
#
# <dir> is the pipeline's --out root (v1/…, feeds/…). The branch always holds exactly one
# parentless commit, so the repository does not accumulate ~60 MB of JSON per hour; old data
# commits become unreachable and are garbage-collected by GitHub.
#
# The commit is assembled with plumbing against a temporary index: the working tree, the real
# index and HEAD are never touched, and nothing is copied. It is pushed through this checkout's
# own remote with whatever credentials git has; refresh.yml hands an http.extraheader to this
# script's step only, through GIT_CONFIG_* in the environment.
#
# Nothing is pushed when the content fingerprint (row index, KEV file and headline counts,
# ignoring generated_at) matches the branch. The push is a lease on the commit we compared
# against, so a concurrent publisher can never be silently overwritten, and data older than the
# branch's (a re-run of an old run's publish job) is refused, so the carried state never goes
# back in time. Works on the very first run, when the branch does not exist yet.
#
# Environment (all optional):
#   DATA_BRANCH     branch to publish to (default: data)
#   PUBLISH_REMOTE  remote to push to (default: origin)
#   GITHUB_*        set by GitHub Actions; used for links in the commit message and README
set -euo pipefail

readonly BRANCH="${DATA_BRANCH:-data}"
readonly REMOTE="${PUBLISH_REMOTE:-origin}"
# Files that must exist in <dir>; the first three also make up the change fingerprint.
readonly REQUIRED=(v1/index.json v1/kev.json v1/meta.json v1/signal.json)

# Data commits are machine-made: default to the Actions bot identity unless the caller set one.
export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-github-actions[bot]}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
export GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-$GIT_AUTHOR_NAME}"
export GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-$GIT_AUTHOR_EMAIL}"

log() { printf 'publish-data-branch: %s\n' "$*"; }
die() { printf 'publish-data-branch: error: %s\n' "$*" >&2; exit 1; }
usage() { printf 'usage: %s [--dry-run] <dir>\n' "${0##*/}" >&2; exit "${1:-2}"; }

dry_run=false
case "${1:-}" in
  --dry-run) dry_run=true; shift ;;
  -h | --help) usage 0 ;;
esac
[[ $# -eq 1 ]] || usage

command -v git >/dev/null || die 'git is required'
command -v jq >/dev/null || die 'jq is required'

[[ -d $1 ]] || die "not a directory: $1"
src=$(cd -- "$1" && pwd -P)
for f in "${REQUIRED[@]}"; do
  [[ -s $src/$f ]] || die "$src does not look like pipeline output: $f is missing or empty"
done

# Operate on the repository this script belongs to, wherever it is called from.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
git_dir=$(git rev-parse --absolute-git-dir)

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/publish-data.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

# owner/repo for links: from Actions, else parsed from a GitHub remote URL.
repo_slug() {
  if [[ -n ${GITHUB_REPOSITORY:-} ]]; then
    printf '%s\n' "$GITHUB_REPOSITORY"
    return
  fi
  local url
  url=$(git remote get-url "$REMOTE")
  url=${url%.git}
  case "$url" in
    https://github.com/*) printf '%s\n' "${url#https://github.com/}" ;;
    git@github.com:*) printf '%s\n' "${url#git@github.com:}" ;;
    *) printf 'OWNER/REPO\n' ;;
  esac
}

# Change fingerprint of a data tree. generated_at differs on every run and is ignored, as are the
# woke.json bounds that move with it and the per-ecosystem fetch times in packages.json; any other
# change to the rows, the KEV file, the headline counts, the woke-up list, the receipts, the package
# advisories or the carried state produces a new fingerprint. The state
# must be published whenever it changes, or the next run would forget what this one saw first.
# The Receipts log in it records every run (its last run and run count), so in practice every
# successful run is published.
fingerprint() {
  local dir=$1
  {
    jq -cS 'del(.generated_at)' "$dir/v1/index.json" &&
      jq -cS 'del(.generated_at)' "$dir/v1/kev.json" &&
      jq -cS '.counts' "$dir/v1/meta.json" &&
      if [[ -f $dir/v1/woke.json ]]; then jq -cS 'del(.generated_at, .since, .published_before)' "$dir/v1/woke.json"; fi &&
      if [[ -f $dir/v1/receipts.json ]]; then jq -cS 'del(.generated_at)' "$dir/v1/receipts.json"; fi &&
      if [[ -f $dir/v1/packages.json ]]; then jq -cS 'del(.generated_at) | .sources |= map(del(.fetched_at))' "$dir/v1/packages.json"; fi &&
      if [[ -f $dir/v1/state.json ]]; then jq -cS 'del(.generated_at)' "$dir/v1/state.json"; fi
  } | git hash-object --stdin
}

# Fingerprint of a published commit; fails when it lacks any of the fingerprinted files, so a
# branch from before woke.json, receipts.json, state.json and packages.json existed is always
# republished.
commit_fingerprint() {
  local dir="$work/published"
  mkdir -p "$dir"
  git archive "$1" -- v1/index.json v1/kev.json v1/meta.json v1/woke.json v1/receipts.json v1/state.json v1/packages.json | tar -x -C "$dir" || return 1
  fingerprint "$dir"
}

# README.md of the data branch. Markdown is generated from the data itself where possible so it
# cannot drift from what the pipeline emits.
data_readme() {
  local repo=$1 scope window year
  scope=$(jq -r '.scope' "$src/v1/signal.json")
  window=$(jq -r '.window.days' "$src/v1/meta.json")
  year=$(jq -r '.generated_at[0:4]' "$src/v1/meta.json")
  cat <<EOF
# Data branch

Machine-generated data for [${repo}](https://github.com/${repo}). The \`refresh-data\` workflow
rebuilds it every hour and force-pushes it as a single commit without history: do not commit
here, and do not pin old commits — they are garbage-collected.

## JSON API (schema v1)

Base URL: \`https://raw.githubusercontent.com/${repo}/${BRANCH}/\`

| Path | Contents |
|---|---|
| \`v1/meta.json\` | Run metadata: ${window}-day window, headline counts with definitions, score model, source health |
| \`v1/signal.json\` | Rows worth a look (${scope}); columnar |
| \`v1/index.json\` | Every CVE published in the last ${window} days; columnar |
| \`v1/cve/<xx>.json\` | Full per-CVE detail with every reason chip; \`<xx>\` is the FNV-1a shard of the CVE ID |
| \`v1/batches.json\` | Patch-day batches: 50+ CVEs from one CNA on one day |
| \`v1/kev.json\` | Recent CISA KEV additions and upcoming due dates |
| \`v1/stats.json\` | Monthly history since 1999, daily and hourly counts, top CNAs, AI credits |
| \`v1/changes.json\` | Escalations (tier went up, or new exploit evidence) in the last 7 days |
| \`v1/woke.json\` | Old CVEs (published before the window) that gained exploitation evidence in the last 30 days |
| \`v1/receipts.json\` | Receipts: how often CVErdict flagged a CVE before CISA listed it in KEV (forward log and hindsight backtest) |
| \`v1/packages.json\` | Package versions the CVEs with a detail shard affect, from OSV.dev advisories, with each CVE's row (for the in-browser SBOM check) |
| \`v1/state.json\` | Internal state carried between runs; unstable, do not build on it |
| \`feeds/signal.xml\` | Atom: newest Exploited and Likely-next CVEs |
| \`feeds/kev.xml\` | Atom: KEV additions |
| \`feeds/kev-due.ics\` | iCalendar: KEV remediation due dates |
| \`feeds/woke.xml\` | Atom: old CVEs that woke up |

Every JSON file carries \`schema_version\` and \`generated_at\`. Fields, sharding and the
versioning policy are documented in
[docs/DATA.md](https://github.com/${repo}/blob/HEAD/docs/DATA.md).

\`\`\`sh
curl -s https://raw.githubusercontent.com/${repo}/${BRANCH}/v1/meta.json | jq .counts
\`\`\`

## License and attribution

Scores, tiers and reason chips are dedicated to the public domain (CC0-1.0). Upstream data in
these files stays under its own terms:

- **CVE List** (IDs, dates, titles, descriptions, affected products, CVSS, CWE, references): the
  [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse), whose notice follows.
- **CISA KEV and Vulnrichment** (KEV entries, SSVC): CC0-1.0. Use of the information does not
  authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an
  endorsement by CISA or DHS.
- **EPSS**: by the [FIRST EPSS SIG](https://www.first.org/epss), free to use with attribution.
- **Exploit feeds**: identifiers and links only, no exploit code. Metasploit Framework
  (BSD-3-Clause, © Rapid7, Inc.), Nuclei templates (MIT, © ProjectDiscovery, Inc.), Exploit-DB
  (GPL-2.0), PoC-in-GitHub (CC0-1.0).
- **Package advisories** in \`v1/packages.json\`, through [OSV.dev](https://osv.dev): GitHub Advisory
  Database (CC-BY-4.0), PyPI Advisory Database (CC-BY-4.0), Go Vulnerability Database (CC-BY-4.0),
  RustSec Advisory Database (CC0-1.0) and Drupal security advisories (MIT, Copyright (c) 2025
  Ackama; the full notice is in the file's \`attribution\` and in ATTRIBUTIONS.md). Only advisory
  IDs, package names and version ranges are kept, for the CVEs this data covers.

Full notices and license texts:
[ATTRIBUTIONS.md](https://github.com/${repo}/blob/HEAD/ATTRIBUTIONS.md).

> Copyright © 1999-${year}, The MITRE Corporation. CVE is a trademark and the CVE logo is a
> registered trademark of The MITRE Corporation.
>
> **CVE Usage:** MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge,
> royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly
> display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures
> (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's
> copyright designation and this license in any such copy.
EOF
  # Notices that must travel with copies of packages.json (the Drupal advisories' MIT license),
  # taken from the file itself, whose attribution validate.ts checks against shared/packages.ts.
  if [[ -f $src/v1/packages.json ]]; then
    jq -r '.attribution[] | select(.notice != null) | "\n### \(.name) (\(.license))\n\n```text\n\(.notice)\n```"' "$src/v1/packages.json"
  fi
}

commit_message() {
  jq -r '"Data \(.generated_at)\n\n\(.counts.window_published) CVEs in the \(.window.days)-day window, \(.counts.window_passed) exploited or likely next; score model \(.score_model)."' "$src/v1/meta.json"
  printf '\nSource: %s\n' "$(git rev-parse HEAD)"
  if [[ -n ${GITHUB_RUN_ID:-} ]]; then
    printf 'Run: %s/%s/actions/runs/%s\n' "${GITHUB_SERVER_URL:-https://github.com}" "$(repo_slug)" "$GITHUB_RUN_ID"
  fi
}

# Current tip of the branch on the remote ("" when it does not exist yet).
remote_tip=''
status=0
git ls-remote --exit-code --heads "$REMOTE" "refs/heads/$BRANCH" >/dev/null || status=$?
case $status in
  0)
    # Data commits are parentless, so this transfers one commit's objects and no history.
    git fetch --quiet --no-tags "$REMOTE" "refs/heads/$BRANCH"
    remote_tip=$(git rev-parse --verify 'FETCH_HEAD^{commit}')
    ;;
  2) log "$REMOTE has no $BRANCH branch yet; it will be created" ;;
  *) die "could not list $REMOTE (git ls-remote exited with $status)" ;;
esac

# Never replace newer data with older data. Re-running an old run's failed publish job would
# otherwise roll back state.json for good: the Receipts log would lose the runs and first flags
# recorded since. Both values are the pipeline's ISO-8601 UTC strings, so they compare as text.
if [[ -n $remote_tip ]]; then
  remote_gen=$(git show "$remote_tip:v1/meta.json" 2>/dev/null | jq -r '.generated_at // empty' 2>/dev/null || true)
  local_gen=$(jq -r '.generated_at // empty' "$src/v1/meta.json")
  if [[ -n $remote_gen && -n $local_gen ]] && jq -en --arg r "$remote_gen" --arg l "$local_gen" '$r > $l' >/dev/null; then
    die "the $BRANCH branch already holds newer data ($remote_gen) than this run ($local_gen); start a new run instead of re-running an old one"
  fi
fi

local_fp=$(fingerprint "$src")
if [[ -n $remote_tip ]]; then
  if remote_fp=$(commit_fingerprint "$remote_tip") && [[ $remote_fp == "$local_fp" ]]; then
    log "content unchanged since ${remote_tip:0:12}; nothing to publish"
    exit 0
  fi
fi

# Build the tree from <dir> plus the generated files, using a throwaway index.
export GIT_INDEX_FILE="$work/index"
git -C "$src" --git-dir="$git_dir" --work-tree="$src" add --all --force -- .
readme_blob=$(data_readme "$(repo_slug)" | git hash-object -w --stdin)
git update-index --add --cacheinfo "100644,$readme_blob,README.md"
# Vercel would otherwise build a preview deployment of this branch on every push.
vercel_blob=$(printf '{ "git": { "deploymentEnabled": false } }\n' | git hash-object -w --stdin)
git update-index --add --cacheinfo "100644,$vercel_blob,vercel.json"
tree=$(git write-tree)
unset GIT_INDEX_FILE

commit=$(commit_message | git commit-tree "$tree")
files=$(git ls-tree -r --name-only "$commit" | wc -l | tr -d ' ')

if $dry_run; then
  log "dry run: built ${commit:0:12} ($files files); not pushing to $REMOTE/$BRANCH"
  exit 0
fi

# An empty expected value means "the branch must not exist yet".
git push --quiet --force-with-lease="refs/heads/$BRANCH:$remote_tip" "$REMOTE" "$commit:refs/heads/$BRANCH"
log "published ${commit:0:12} ($files files) to $REMOTE/$BRANCH"
