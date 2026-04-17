#!/usr/bin/env bash
# nightly-scan.sh — pull each TARGET_IMAGES entry, push into the local
# compose registry, poll /v2/scan/live/{digest} until completed, then write:
#
#   scan-reports/<safe-name>.json   (raw scanner response per image)
#   scan-reports/summary.txt        (human-readable workflow-log output)
#   scan-summary.json               (Slack Blocks payload)
#
# Requires the compose stack to be up and registry/auth reachable at
# ${REGISTRY} (default localhost:5000). Auth is basic — admin/admin per
# docker-compose.yml.
set -euo pipefail

REGISTRY=${REGISTRY:-localhost:5000}
REGISTRY_USER=${REGISTRY_USER:-admin}
REGISTRY_PASS=${REGISTRY_PASS:-admin}
TENANT=${TENANT:-demo}
PROJECT=${PROJECT:-default}
TARGET_IMAGES=${TARGET_IMAGES:-"alpine:3.16,python:3.9-slim,nginx:1.23"}
POLL_TIMEOUT_SECS=${POLL_TIMEOUT_SECS:-600}
POLL_INTERVAL_SECS=${POLL_INTERVAL_SECS:-5}
FAIL_ON_CRITICAL=${FAIL_ON_CRITICAL:-false}

mkdir -p scan-reports
: > scan-reports/summary.txt

# Pre-fetch a registry pull/push token we can reuse across pushes. The
# /auth/token service returns a short-lived JWT the registry verifies.
get_scan_token() {
  local scope="$1"
  curl -sf -u "${REGISTRY_USER}:${REGISTRY_PASS}" \
    "http://${REGISTRY}/auth/token?service=nebulacr-registry&scope=${scope}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])"
}

scan_one() {
  local src="$1"              # e.g. alpine:3.16
  local name version safe dest
  name="${src%%:*}"
  version="${src##*:}"
  safe="$(echo "${src}" | tr '/:' '_')"
  dest="${REGISTRY}/${TENANT}/${PROJECT}/${name}:${version}"

  echo "::group::scan ${src}"
  docker pull --quiet "${src}" >/dev/null
  docker tag "${src}" "${dest}"
  docker push "${dest}" >/dev/null

  local digest
  digest="$(docker inspect --format='{{index .RepoDigests 0}}' "${dest}" 2>/dev/null | awk -F@ '{print $2}')"
  if [ -z "${digest}" ]; then
    # Fallback: query the registry manifest endpoint.
    local tok
    tok="$(get_scan_token "repository:${TENANT}/${PROJECT}/${name}:pull")"
    digest="$(curl -sf -I \
      -H "Authorization: Bearer ${tok}" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
      "http://${REGISTRY}/v2/${TENANT}/${PROJECT}/${name}/manifests/${version}" \
      | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
  fi
  echo "digest: ${digest}"

  # Poll the scanner. The scan is kicked by the push webhook; the endpoint
  # returns 404 until the worker picks the job, queued/in_progress while
  # running, and completed/failed at terminal states.
  local tok body status deadline
  tok="$(get_scan_token "repository:${TENANT}/${PROJECT}/${name}:pull")"
  deadline=$(( $(date +%s) + POLL_TIMEOUT_SECS ))
  while :; do
    body="$(curl -sS -H "Authorization: Bearer ${tok}" "http://${REGISTRY}/v2/scan/live/${digest}" || true)"
    status="$(echo "${body}" | jq -r '.status // "unknown"')"
    case "${status}" in
      completed|failed) break ;;
    esac
    [ "$(date +%s)" -lt "${deadline}" ] || { echo "::error::scan timeout after ${POLL_TIMEOUT_SECS}s on ${src}"; status="timeout"; break; }
    sleep "${POLL_INTERVAL_SECS}"
  done

  local report="scan-reports/${safe}.json"
  echo "${body}" | jq '.' > "${report}"

  # Human summary per image
  python3 - "${src}" "${digest}" "${status}" "${report}" >> scan-reports/summary.txt <<'PY'
import json, sys
src, digest, status, report = sys.argv[1:5]
d = json.load(open(report))
r = d.get("result") or {}
s = r.get("summary") or {}
pe = r.get("policy_evaluation") or {}
verdict = pe.get("status", "-")
print(f"── {src}  ({digest[:19]}…)  status={status}  verdict={verdict}")
print(f"   critical={s.get('critical',0)}  high={s.get('high',0)}  "
      f"medium={s.get('medium',0)}  low={s.get('low',0)}  unk={s.get('unknown',0)}")
top = [v for v in (r.get("vulnerabilities") or [])
       if (v.get("severity") or "").upper() == "CRITICAL" and not v.get("suppressed")]
for v in top[:3]:
    fixed = v.get("fixed_version") or "—"
    print(f"   CRITICAL {v['id']}  {v['package']}@{v['installed_version']} → {fixed}")
print()
PY

  echo "::endgroup::"
}

# ── run all images ───────────────────────────────────────────────────────────
IFS=',' read -ra IMAGE_ARR <<< "${TARGET_IMAGES}"
for img in "${IMAGE_ARR[@]}"; do
  scan_one "$(echo "$img" | xargs)"  # trim whitespace
done

echo "============ NIGHTLY CVE SCAN SUMMARY ============"
cat scan-reports/summary.txt
echo "=================================================="

# ── Slack payload (Blocks) ───────────────────────────────────────────────────
python3 - > scan-summary.json <<'PY'
import json, os, glob, datetime
reports = sorted(glob.glob("scan-reports/*.json"))
totals = {k:0 for k in ("critical","high","medium","low","unknown")}
rows = []
any_fail = False
for p in reports:
    d = json.load(open(p))
    r = d.get("result") or {}
    s = r.get("summary") or {}
    pe = r.get("policy_evaluation") or {}
    verdict = pe.get("status") or "-"
    if verdict == "FAIL": any_fail = True
    img = f"{r.get('tenant','?')}/{r.get('project','?')}/{r.get('repository','?')}:{r.get('reference','?')}"
    for k in totals: totals[k] += int(s.get(k,0))
    rows.append({
        "image": img,
        "status": d.get("status", "?"),
        "verdict": verdict,
        **{k:int(s.get(k,0)) for k in totals},
    })

ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
emoji = "🚨" if any_fail else ("⚠️" if totals["critical"]+totals["high"]>0 else "✅")
header = f"{emoji} NebulaCR nightly CVE scan — {ts}"
table = "\n".join(
    f"• `{r['image']}` — *{r['verdict']}* "
    f"(C:{r['critical']} H:{r['high']} M:{r['medium']} L:{r['low']})"
    for r in rows
) or "_(no images scanned)_"

payload = {
    "text": header,
    "blocks": [
        {"type":"header","text":{"type":"plain_text","text":header}},
        {"type":"section","text":{"type":"mrkdwn","text": table}},
        {"type":"context","elements":[{"type":"mrkdwn",
            "text": f"totals — crit:*{totals['critical']}* high:*{totals['high']}* "
                    f"med:{totals['medium']} low:{totals['low']} unk:{totals['unknown']}"}]},
    ],
}
print(json.dumps(payload))
PY

echo "slack_payload=1" >> "${GITHUB_OUTPUT:-/dev/null}"

# Optional fail-on-critical gate — turned off by default so a dirty scan
# doesn't page at 03:00, but flip the dispatch input to opt in.
if [ "${FAIL_ON_CRITICAL}" = "true" ]; then
  crits=$(jq -s 'map((.result.summary.critical // 0)) | add // 0' scan-reports/*.json)
  if [ "${crits}" -gt 0 ]; then
    echo "::error::found ${crits} critical CVEs across target images"
    exit 1
  fi
fi
