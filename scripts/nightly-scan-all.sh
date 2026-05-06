#!/usr/bin/env bash
# nightly-scan-all.sh — nightly integration test: scan every image in the
# registry (not a hard-coded list).
#
# Flow:
#   1. GET /v2/_catalog                    → list of tenant/project/name repos
#   2. GET /v2/{repo}/tags/list            → tags per repo
#   3. HEAD /v2/{repo}/manifests/{tag}     → resolve digest
#   4. poll /v2/scan/live/{digest}         → until completed/failed/timeout
#   5. write scan-reports/<safe>.json per (repo, tag)
#   6. python scripts/nightly-report-pdf.py → scan-reports/report.pdf
#   7. python scripts/slack-upload-pdf.py   → upload to Slack
#
# Differs from nightly-scan.sh in step 1–2: enumerate what's actually in the
# registry instead of iterating TARGET_IMAGES.
set -euo pipefail

REGISTRY=${REGISTRY:-localhost:5000}
REGISTRY_USER=${REGISTRY_USER:-admin}
REGISTRY_PASS=${REGISTRY_PASS:-admin}
SCHEME=${SCHEME:-http}
POLL_TIMEOUT_SECS=${POLL_TIMEOUT_SECS:-600}
POLL_INTERVAL_SECS=${POLL_INTERVAL_SECS:-5}
CATALOG_PAGE_SIZE=${CATALOG_PAGE_SIZE:-10000}
FAIL_ON_CRITICAL=${FAIL_ON_CRITICAL:-false}

mkdir -p scan-reports scan-reports/.digests
: > scan-reports/summary.txt
# Reset the per-run digest cache so a previous run's symlinks don't shadow
# this run's first-seen report files.
rm -f scan-reports/.digests/*

# jq is used for response parsing; install on the fly if the runner image
# doesn't ship it (skopeo/stable is Fedora-based and sometimes lacks jq).
if ! command -v jq >/dev/null 2>&1; then
  (microdnf install -y jq >/dev/null 2>&1 \
    || dnf install -y jq >/dev/null 2>&1 \
    || (apt-get update -qq && apt-get install -y -qq jq >/dev/null 2>&1)) \
  || { echo "jq missing and auto-install failed" >&2; exit 1; }
fi

get_token() {
  local scope="$1"
  curl -sf -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
    "${SCHEME}://${REGISTRY}/auth/token?service=nebulacr-registry&scope=${scope}" \
    | jq -r '.token'
}

# The catalog handler filters by the admin token's tenant claim, not by the
# scope string, so any parseable pull scope is enough to mint a valid JWT.
CATALOG_TOK=$(get_token "repository:catalog:*")

CATALOG_JSON=$(curl -sf -H "Authorization: Bearer ${CATALOG_TOK}" \
  "${SCHEME}://${REGISTRY}/v2/_catalog?n=${CATALOG_PAGE_SIZE}")
REPOS=$(echo "$CATALOG_JSON" | jq -r '.repositories[]?')

if [ -z "$REPOS" ]; then
  echo "::warning::registry catalog is empty — nothing to scan"
fi

echo "Discovered repositories:"
echo "${REPOS:-  (none)}" | sed 's/^/  /'
echo

scan_one() {
  local repo="$1" tag="$2"
  local safe
  safe=$(printf '%s' "${repo}:${tag}" | tr '/:' '__')

  local pull_tok digest
  pull_tok=$(get_token "repository:${repo}:pull")

  # HEAD the manifest to resolve the digest without pulling the body. The
  # Accept list covers both OCI and legacy Docker manifests (single + index).
  digest=$(curl -sf -I \
    -H "Authorization: Bearer ${pull_tok}" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" \
    "${SCHEME}://${REGISTRY}/v2/${repo}/manifests/${tag}" \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')

  if [ -z "$digest" ]; then
    echo "::warning::no digest for ${repo}:${tag} — skipping" >&2
    return 0
  fi
  echo "digest: ${digest}"

  # Digest dedup: if this digest has already been scanned for some other
  # (repo, tag) in this run, reuse that report instead of polling the API
  # again. The marker file holds the safe filename of the first occurrence.
  local digest_marker="scan-reports/.digests/${digest//[^A-Za-z0-9]/_}"
  local report="scan-reports/${safe}.json"
  if [ -f "$digest_marker" ]; then
    local first_safe
    first_safe=$(cat "$digest_marker")
    cp "scan-reports/${first_safe}.json" "$report"
    {
      local sev
      sev=$(jq -r '
        def s(k): .result.summary[k] // 0;
        "status=\(.status // "?")  verdict=\(.result.policy_evaluation.status // "-")  " +
        "critical=\(s("critical"))  high=\(s("high"))  medium=\(s("medium"))  " +
        "low=\(s("low"))  unknown=\(s("unknown"))"
      ' "$report")
      echo "── ${repo}:${tag}  (${digest:0:19}…)  ${sev}  [deduped from ${first_safe}]"
    } >> scan-reports/summary.txt
    return 0
  fi

  local body status deadline
  deadline=$(( $(date +%s) + POLL_TIMEOUT_SECS ))
  while :; do
    body=$(curl -sS -H "Authorization: Bearer ${pull_tok}" \
      "${SCHEME}://${REGISTRY}/v2/scan/live/${digest}" || true)
    status=$(echo "$body" | jq -r '.status // "unknown"')
    case "$status" in
      completed|failed) break ;;
    esac
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "::error::scan timeout after ${POLL_TIMEOUT_SECS}s on ${repo}:${tag}" >&2
      status="timeout"
      break
    fi
    sleep "${POLL_INTERVAL_SECS}"
  done

  echo "$body" | jq '.' > "$report"
  # Only mark this digest as "scanned this run" when it completed cleanly.
  # If the poll timed out or the scanner reported failed, a different
  # (repo, tag) for the same digest might still succeed on retry — so we
  # leave the marker unset and let the next occurrence re-scan.
  if [ "${status}" = "completed" ]; then
    printf '%s' "$safe" > "$digest_marker"
  fi

  {
    local sev
    sev=$(jq -r '
      def s(k): .result.summary[k] // 0;
      "status=\(.status // "?")  verdict=\(.result.policy_evaluation.status // "-")  " +
      "critical=\(s("critical"))  high=\(s("high"))  medium=\(s("medium"))  " +
      "low=\(s("low"))  unknown=\(s("unknown"))"
    ' "$report")
    echo "── ${repo}:${tag}  (${digest:0:19}…)  ${sev}"
  } >> scan-reports/summary.txt
}

while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  pull_tok=$(get_token "repository:${repo}:pull")
  tags_json=$(curl -sf -H "Authorization: Bearer ${pull_tok}" \
    "${SCHEME}://${REGISTRY}/v2/${repo}/tags/list" || echo '{}')
  mapfile -t tags < <(echo "$tags_json" | jq -r '.tags[]?')
  if [ ${#tags[@]} -eq 0 ]; then
    echo "::warning::no tags for ${repo}"
    continue
  fi
  for tag in "${tags[@]}"; do
    echo "::group::${repo}:${tag}"
    scan_one "$repo" "$tag" || echo "scan failed for ${repo}:${tag}" >&2
    echo "::endgroup::"
  done
done <<< "$REPOS"

echo "============ NIGHTLY CVE SCAN SUMMARY (ALL IMAGES) ============"
cat scan-reports/summary.txt
echo "==============================================================="

# Generate PDF and (optionally) upload to Slack. Both scripts are no-ops if
# their inputs aren't available — e.g. no reports, or no SLACK_BOT_TOKEN.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
python3 "${SCRIPT_DIR}/nightly-report-pdf.py" scan-reports scan-reports/report.pdf
python3 "${SCRIPT_DIR}/slack-upload-pdf.py" scan-reports/report.pdf

if [ "${FAIL_ON_CRITICAL}" = "true" ]; then
  crits=$(jq -s 'map((.result.summary.critical // 0)) | add // 0' scan-reports/*.json 2>/dev/null || echo 0)
  if [ "${crits:-0}" -gt 0 ]; then
    echo "::error::found ${crits} critical CVEs across all scanned images"
    exit 1
  fi
fi
