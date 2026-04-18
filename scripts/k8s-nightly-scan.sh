#!/usr/bin/env bash
# k8s-nightly-scan.sh — in-cluster nightly CVE scan.
#
# For each image in $TARGET_IMAGES: copy it into NebulaCR with skopeo (no
# docker daemon needed), resolve the pushed digest, poll
# /v2/scan/live/{digest} until completed/failed/timeout, then POST a
# Slack Blocks summary to $SLACK_WEBHOOK_URL.
#
# Designed to run inside the k3s cluster, reaching the registry via its
# ClusterIP service — that's why it uses HTTP and --dest-tls-verify=false
# by default. Cross-cluster use would need REGISTRY_SCHEME=https.
set -euo pipefail

REGISTRY="${REGISTRY_HOST:-nebulacr-registry.acc.svc.cluster.local:5000}"
SCHEME="${REGISTRY_SCHEME:-http}"
TENANT="${TENANT:-demo}"
PROJECT="${PROJECT:-default}"
TARGET_IMAGES="${TARGET_IMAGES:-alpine:3.16,python:3.9-slim,nginx:1.23}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-600}"
POLL_INTERVAL_SECS="${POLL_INTERVAL_SECS:-5}"
WORK_DIR="${WORK_DIR:-/work}"
: "${REGISTRY_USER:?missing REGISTRY_USER}"
: "${REGISTRY_PASS:?missing REGISTRY_PASS}"

# skopeo/stable is Fedora-based and ships curl, but jq isn't always there.
if ! command -v jq >/dev/null 2>&1; then
  (microdnf install -y jq >/dev/null 2>&1 \
    || dnf install -y jq >/dev/null 2>&1 \
    || (apt-get update -qq && apt-get install -y -qq jq >/dev/null 2>&1)) \
  || { echo "failed to install jq" >&2; exit 1; }
fi

dest_tls="--dest-tls-verify=false"
inspect_tls="--tls-verify=false"
if [ "$SCHEME" = "https" ]; then
  dest_tls="--dest-tls-verify=true"
  inspect_tls="--tls-verify=true"
fi

mkdir -p "$WORK_DIR/scan-reports"
cd "$WORK_DIR"
: > scan-reports/summary.txt

get_token() {
  curl -fsS -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
    "${SCHEME}://${REGISTRY}/auth/token?service=nebulacr-registry&scope=$1" \
    | jq -r .token
}

scan_one() {
  local src="$1"
  local name="${src%%:*}"
  local version="${src##*:}"
  local dest="docker://${REGISTRY}/${TENANT}/${PROJECT}/${name}:${version}"
  local safe; safe=$(printf '%s' "$src" | tr '/:' '_')

  echo "::group::scan ${src}"
  skopeo copy --retry-times 3 $dest_tls \
    --dest-creds "${REGISTRY_USER}:${REGISTRY_PASS}" \
    "docker://docker.io/library/${src}" "${dest}"

  local digest
  digest=$(skopeo inspect $inspect_tls \
    --creds "${REGISTRY_USER}:${REGISTRY_PASS}" "${dest}" | jq -r .Digest)
  echo "digest: ${digest}"

  local tok body status deadline
  tok=$(get_token "repository:${TENANT}/${PROJECT}/${name}:pull")
  deadline=$(( $(date +%s) + POLL_TIMEOUT_SECS ))
  while :; do
    body=$(curl -sS -H "Authorization: Bearer ${tok}" \
      "${SCHEME}://${REGISTRY}/v2/scan/live/${digest}" || true)
    status=$(echo "$body" | jq -r '.status // "unknown"')
    case "$status" in
      completed|failed) break ;;
    esac
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "scan timeout after ${POLL_TIMEOUT_SECS}s on ${src}" >&2
      status="timeout"
      break
    fi
    sleep "${POLL_INTERVAL_SECS}"
  done

  local report="scan-reports/${safe}.json"
  echo "$body" | jq . > "$report"

  {
    echo "── ${src}  (${digest:0:19}…)  status=${status}"
    jq -r '
      def s(k): .result.summary[k] // 0;
      "   verdict=\(.result.policy_evaluation.status // "-")  critical=\(s("critical"))  high=\(s("high"))  medium=\(s("medium"))  low=\(s("low"))  unknown=\(s("unknown"))"
    ' "$report"
    echo
  } >> scan-reports/summary.txt
  echo "::endgroup::"
}

IFS=',' read -ra IMAGE_ARR <<< "${TARGET_IMAGES}"
for img in "${IMAGE_ARR[@]}"; do
  img="$(echo "$img" | xargs)"
  [ -z "$img" ] && continue
  scan_one "$img" || echo "scan failed for $img" >&2
done

echo "============ NIGHTLY CVE SCAN SUMMARY ============"
cat scan-reports/summary.txt
echo "=================================================="

if [ -z "${SLACK_WEBHOOK_URL:-}" ]; then
  echo "SLACK_WEBHOOK_URL not set; skipping Slack post." >&2
  exit 0
fi

ts=$(date -u +"%Y-%m-%d %H:%M UTC")
shopt -s nullglob
reports=(scan-reports/*.json)
shopt -u nullglob

if [ ${#reports[@]} -eq 0 ]; then
  payload=$(jq -n --arg ts "$ts" \
    '{text: ("NebulaCR nightly CVE scan — " + $ts + " (no images scanned)")}')
else
  # Per-image block = one row line + up to TOP_N lines of critical/high
  # CVEs (CRITICAL first, then HIGH; suppressed excluded). Cap keeps the
  # Slack section under the 3000-char mrkdwn limit for ~5 images.
  payload=$(jq -s --arg ts "$ts" --argjson top "${TOP_N_CVES:-3}" '
    (map(.result.summary.critical // 0) | add // 0) as $c |
    (map(.result.summary.high     // 0) | add // 0) as $h |
    (map(.result.summary.medium   // 0) | add // 0) as $m |
    (map(.result.summary.low      // 0) | add // 0) as $l |
    (map(.result.summary.unknown  // 0) | add // 0) as $u |
    (any(.result.policy_evaluation.status == "FAIL")) as $anyfail |
    (map(
      . as $d |
      "• `\($d.result.tenant // "?")/\($d.result.project // "?")/\($d.result.repository // "?"):\($d.result.reference // "?")` — *\($d.result.policy_evaluation.status // "-")* (C:\($d.result.summary.critical // 0) H:\($d.result.summary.high // 0) M:\($d.result.summary.medium // 0) L:\($d.result.summary.low // 0))" as $row |
      (
        [ ($d.result.vulnerabilities // [])[]
          | select((.suppressed // false) | not)
          | select(.severity == "CRITICAL" or .severity == "HIGH")
        ]
        | sort_by(if .severity == "CRITICAL" then 0 else 1 end)
        | .[0:$top]
        | map("    `\(.severity)` \(.id) `\(.package)@\(.installed_version)` → `\(.fixed_version // "—")`")
        | join("\n")
      ) as $detail |
      if $detail == "" then $row else "\($row)\n\($detail)" end
    ) | join("\n")) as $table |
    (if $anyfail then "🚨" elif ($c + $h) > 0 then "⚠️" else "✅" end) as $emoji |
    ("\($emoji) NebulaCR nightly CVE scan — \($ts)") as $hdr |
    {
      text: $hdr,
      blocks: [
        {type:"header",  text:{type:"plain_text", text:$hdr}},
        {type:"section", text:{type:"mrkdwn", text:(if $table=="" then "_(no images scanned)_" else $table end)}},
        {type:"context", elements:[{type:"mrkdwn",
          text:"totals — crit:*\($c)* high:*\($h)* med:\($m) low:\($l) unk:\($u)"}]}
      ]
    }
  ' "${reports[@]}")
fi

if curl -fsS -X POST -H 'Content-Type: application/json' \
     --data "$payload" "$SLACK_WEBHOOK_URL" >/dev/null; then
  echo "Slack summary posted."
else
  echo "Slack post failed" >&2
  exit 1
fi
