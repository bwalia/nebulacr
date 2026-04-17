#!/usr/bin/env bash
# gate-on-scan.sh — poll NebulaCR for a scan verdict and fail the build if it's not PASS.
#
# Required env:
#   NEBULACR_URL        e.g. https://nebulacr.example.com
#   NEBULACR_SCAN_KEY   scanner API key (nck_*) with scan:read
#   IMAGE_DIGEST        sha256:... from your build step
#
# Optional env:
#   SCAN_TIMEOUT_SECS   default 600
#   POLL_INTERVAL_SECS  default 5
set -euo pipefail

: "${NEBULACR_URL:?}"
: "${NEBULACR_SCAN_KEY:?}"
: "${IMAGE_DIGEST:?}"

timeout=${SCAN_TIMEOUT_SECS:-600}
interval=${POLL_INTERVAL_SECS:-5}
deadline=$(( $(date +%s) + timeout ))

while :; do
  body=$(curl -sS --fail \
    -H "Authorization: Bearer ${NEBULACR_SCAN_KEY}" \
    "${NEBULACR_URL}/v2/scan/live/${IMAGE_DIGEST}") || { echo "scan fetch failed" >&2; exit 3; }
  status=$(echo "$body" | jq -r '.status')

  case "$status" in
    completed)
      verdict=$(echo "$body" | jq -r '.result.policy_evaluation.status // "UNKNOWN"')
      summary=$(echo "$body" | jq -c '.result.summary')
      echo "scan complete: verdict=${verdict} summary=${summary}"
      [[ "$verdict" == "PASS" ]] && exit 0
      echo "$body" | jq '.result.policy_evaluation.violations'
      exit 1
      ;;
    queued|in_progress)
      [[ $(date +%s) -lt $deadline ]] || { echo "scan timeout after ${timeout}s" >&2; exit 2; }
      sleep "$interval"
      ;;
    failed|not_found)
      echo "scan ${status}" >&2
      exit 3
      ;;
    *)
      echo "unexpected status ${status}" >&2
      exit 4
      ;;
  esac
done
