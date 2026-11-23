#!/usr/bin/env bash
# Fast check between hourly refreshes (.github/workflows/fast-check.yml, docs/DEPLOY.md "Fast check").
#
#   scripts/fast-check.sh
#
# Compares the CISA KEV catalog (and, once an hour, ENISA's EU KEV list) with the snapshot the last
# published run saw (`catalogs` in v1/events.json). When upstream lists different CVEs, it starts
# refresh.yml now instead of waiting for the next hourly run. It never writes data: the full
# pipeline does that, so every file stays consistent.
#
# It needs no state of its own: CISA is asked "changed since the pipeline's own download?"
# (If-Modified-Since = catalogs.kev.fetched_at), and every answer is compared by a hash of the
# sorted CVE ids, the same as pipeline/src/events.ts idsHash().
#
# Timing comes from the runs, not from the clock minute this run happens to start at (GitHub's
# cron is late and irregular): the hour's phase is the time since the newest hourly timer run
# (a workflow_dispatch that is not ours, in the last 2 hours), else since minute 47.
#
# Stops without dispatching when:
#   - a refresh run is queued or running (it will see the change), or the next hourly run is due
#     within 10 minutes;
#   - a fast-check dispatch is younger than 45 minutes (EU KEV: 20 hours);
#   - the newest successful refresh started after CISA's Last-Modified (it saw this version), or,
#     for an answer without Last-Modified (the GitHub mirror), after our own dispatch of the last
#     3 hours (that run saw upstream, and the ids still differ: dispatching again would loop).
# Any network or API error is a warning and exit 0: the hourly run is the safety net.
#
# bash, curl, jq, sha256sum and gh only. Environment (all optional; tests set them):
#   RAW_BASE        published data (default https://raw.githubusercontent.com/$GITHUB_REPOSITORY/data)
#   KEV_URLS        space-separated, primary first (default: cisa.gov, then the GitHub mirror)
#   EU_KEV_URL      ENISA's dump
#   GH              gh binary (default gh)
#   NOW             epoch seconds (default: now)
#   CHECK_EU        1 to check EU KEV whatever the phase (default: once an hour, 10 to 25 minutes
#                   after the hourly run started, when it has published)
#   DRY_RUN         1 to report without dispatching
set -euo pipefail

readonly REPO="${GITHUB_REPOSITORY:-markusweldon/cverdict}"
readonly RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/$REPO/data}"
readonly KEV_URLS="${KEV_URLS:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json}"
readonly EU_KEV_URL="${EU_KEV_URL:-https://euvdservices.enisa.europa.eu/api/kev/dump}"
readonly GH="${GH:-gh}"
readonly WORKFLOW=refresh.yml
readonly SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
readonly UA="cverdict-fast-check (+https://github.com/$REPO)"
now="${NOW:-$(date -u +%s)}"
readonly now

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/fast-check.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

# One line each: newlines and carriage returns become spaces, so no text can start a workflow command.
one_line() { local s=${1//$'\r'/ }; printf '%s' "${s//$'\n'/ }"; }
note() { printf '%s\n' "$(one_line "$*")"; printf -- '- %s\n' "$(one_line "$*")" >>"$SUMMARY"; }
# Workflow commands; % and newlines are escaped so upstream text cannot inject more.
esc() { local s=${1//%/%25}; s=${s//$'\r'/%0D}; printf '%s' "${s//$'\n'/%0A}"; }
warn() { printf '::warning title=Fast check::%s\n' "$(esc "$*")"; printf -- '- Warning: %s\n' "$*" >>"$SUMMARY"; }
iso_epoch() { date -u -d "$1" +%s 2>/dev/null || echo 0; }

# The id hash of pipeline/src/events.ts idsHash(): unique, upper-cased, trimmed, valid CVE ids,
# sorted, one per line with a trailing newline, SHA-256 hex. Reads the id list as JSON on stdin.
norm_ids() {
  jq -r '[.[] | strings | ascii_upcase | gsub("^\\s+|\\s+$"; "") | select(test("^CVE-[0-9]{4}-[0-9]{4,}$"))] | unique | .[]'
}
ids_hash() { norm_ids | sha256sum | cut -d' ' -f1; }
ids_count() { norm_ids | wc -l | tr -d ' '; }
# CISA KEV ids the pipeline keeps (sources/kev.ts): entries with a CVE id and a dateAdded.
kev_ids() { jq -c '[.vulnerabilities[]? | objects | select((.dateAdded | type) == "string" and (.dateAdded | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}"))) | .cveID]' "$1"; }
# EU KEV ids (sources/catalogs.ts parseEuKevDump): rows whose sources array has eukev_kev.
eu_ids() { jq -c '[.[]? | objects | select((.sources | type) == "array" and any(.sources[]; . == "eukev_kev")) | .cveId]' "$1"; }

echo "### Fast check" >>"$SUMMARY"

# 1. Refresh runs: skip while one is pending, and rate-limit our own dispatches.
if ! runs=$("$GH" run list --workflow "$WORKFLOW" --limit 30 --json status,conclusion,event,createdAt,displayTitle 2>"$work/gh.err"); then
  warn "Could not list $WORKFLOW runs: $(head -n 1 "$work/gh.err")"
  exit 0
fi
pending=$(jq '[.[] | select(.status != "completed")] | length' <<<"$runs")
if ((pending > 0)); then
  note "A refresh run is queued or running; it will see any change."
  exit 0
fi
since() { jq -r --argjson now "$now" --argjson secs "$1" --arg tag "$2" '[.[] | select(.event == "workflow_dispatch" and (.displayTitle | contains($tag)) and ($now - (.createdAt | sub("\\.[0-9]+"; "") | fromdateiso8601) < $secs))] | length' <<<"$runs"; }
started() { jq -r "[.[] | select($1) | .createdAt | sub(\"\\\\.[0-9]+\"; \"\") | fromdateiso8601] | max // 0" <<<"$runs"; }
last_ok=$(started '.conclusion == "success"')
last_ours=$(started '.event == "workflow_dispatch" and (.displayTitle | contains("fast-check"))')
timer=$(started '.event == "workflow_dispatch" and (.displayTitle | contains("fast-check") | not)')
if ((timer > 0 && now - timer < 7200)); then
  phase=$(((now - timer) % 3600))
  anchor="the last hourly run"
else
  phase=$(((now - 47 * 60) % 3600))
  anchor="minute 47"
fi
if ((phase >= 3000)); then
  note "The next hourly refresh is due in $(((3600 - phase + 59) / 60)) minutes (from $anchor); nothing to do."
  exit 0
fi

# 2. What the last published run saw.
if ! curl -fsS -m 20 -A "$UA" -o "$work/events.json" "$RAW_BASE/v1/events.json" 2>"$work/curl.err"; then
  warn "Could not read the published events.json: $(head -n 1 "$work/curl.err")"
  exit 0
fi
if ! jq -e '.catalogs | type == "object"' "$work/events.json" >/dev/null 2>&1; then
  note "The published data has no catalog snapshot yet; nothing to compare."
  exit 0
fi

changed=()
fresh=none

# 3. CISA KEV, conditional on the pipeline's own download time.
if jq -e '.catalogs.kev.ids_sha256 | type == "string"' "$work/events.json" >/dev/null; then
  want=$(jq -r '.catalogs.kev.ids_sha256' "$work/events.json")
  count=$(jq -r '.catalogs.kev.count' "$work/events.json")
  fetched=$(jq -r '.catalogs.kev.fetched_at // empty' "$work/events.json")
  ims=()
  [[ -n $fetched ]] && ims=(-H "If-Modified-Since: $(date -u -d "$fetched" '+%a, %d %b %Y %H:%M:%S GMT')")
  kev_state=unknown
  for url in $KEV_URLS; do
    code=$(curl -sS -m 20 -A "$UA" "${ims[@]}" -D "$work/kev.h" -o "$work/kev.json" -w '%{http_code}' "$url" 2>"$work/curl.err") || code=000
    if [[ $code == 304 ]]; then
      kev_state=same
      note "CISA KEV: not modified since the published run's download ($url)."
      break
    fi
    if [[ $code == 200 ]] && got=$(kev_ids "$work/kev.json" 2>/dev/null); then
      have=$(ids_hash <<<"$got")
      n=$(ids_count <<<"$got")
      if [[ $have == "$want" ]]; then
        kev_state=same
        note "CISA KEV: same $n CVEs as published."
      else
        modified=$(tr -d '\r' <"$work/kev.h" | sed -n 's/^[Ll]ast-[Mm]odified: *//p' | tail -n 1)
        lm=$([[ -n $modified ]] && iso_epoch "$modified" || echo 0)
        if ((lm > 0 && last_ok > lm + 300)); then
          kev_state=same
          note "CISA KEV: ids differ from the snapshot, but a successful refresh started after this version ($modified); not dispatching."
        elif ((lm == 0 && last_ours > 0 && now - last_ours < 10800 && last_ok > last_ours)); then
          kev_state=same
          note "CISA KEV: $url sends no Last-Modified and its ids differ, but a successful refresh started after our dispatch of the last 3 hours; not dispatching."
        else
          kev_state=changed
          newest=$(jq -r '[.vulnerabilities[]? | objects | select((.cveID | type) == "string" and (.cveID | test("^CVE-[0-9]{4}-[0-9]{4,}$")) and (.dateAdded | type) == "string" and (.dateAdded | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")))] | sort_by(.dateAdded) | reverse | .[:5] | map("\(.cveID) (\(.dateAdded))") | join(", ")' "$work/kev.json")
          note "CISA KEV changed: $n CVEs upstream, $count published. Newest: $newest."
          changed+=(kev)
        fi
      fi
      break
    fi
    warn "CISA KEV: $url answered $code $(head -n 1 "$work/curl.err" 2>/dev/null)"
  done
  [[ $kev_state == unknown ]] && warn "CISA KEV: no source answered; the hourly run will catch up."
fi

# 4. ENISA EU KEV: no validators and a daily refresh, so only once an hour, after the hourly run.
if [[ ${CHECK_EU:-} == 1 ]] || ((phase >= 600 && phase < 1500)); then
  if jq -e '.catalogs.eu_kev.ids_sha256 | type == "string"' "$work/events.json" >/dev/null; then
    want=$(jq -r '.catalogs.eu_kev.ids_sha256' "$work/events.json")
    count=$(jq -r '.catalogs.eu_kev.count' "$work/events.json")
    code=$(curl -sS -m 30 -A "$UA" -o "$work/eu.json" -w '%{http_code}' "$EU_KEV_URL" 2>"$work/curl.err") || code=000
    if [[ $code == 200 ]] && got=$(eu_ids "$work/eu.json" 2>/dev/null); then
      n=$(ids_count <<<"$got")
      if [[ $(ids_hash <<<"$got") == "$want" ]]; then
        note "EU KEV: same $n CVEs as published."
      elif (($(since 72000 eu-kev) > 0)); then
        note "EU KEV: ids differ, but a fast check started a fresh EU KEV run in the last 20 hours; not dispatching."
      else
        note "EU KEV changed: $n CVEs upstream, $count published."
        changed+=(eu-kev)
        fresh=eu-kev
      fi
    else
      warn "EU KEV: $EU_KEV_URL answered $code $(head -n 1 "$work/curl.err" 2>/dev/null)"
    fi
  fi
fi

# 5. Dispatch.
if ((${#changed[@]} == 0)); then
  note "Nothing new upstream."
  exit 0
fi
if (($(since 2700 fast-check) > 0)); then
  note "Changed (${changed[*]}), but a fast check dispatched a refresh in the last 45 minutes; the next one will follow."
  exit 0
fi
if [[ ${DRY_RUN:-} == 1 ]]; then
  note "Dry run: would start $WORKFLOW (reason fast-check, fresh $fresh)."
  exit 0
fi
if "$GH" workflow run "$WORKFLOW" -f reason=fast-check -f fresh="$fresh" 2>"$work/gh.err"; then
  note "Started $WORKFLOW (reason fast-check, fresh $fresh) for: ${changed[*]}."
else
  warn "Could not start $WORKFLOW: $(head -n 1 "$work/gh.err")"
fi
