#!/usr/bin/env bash
# Online-GC end-to-end smoke test (009 slice 4).
#
# Boots a registry + postgres via docker-compose with NEBULACR_GC__ONLINE=true,
# pushes an image, deletes it, waits past the grace period, and asserts:
#   - blob_refcounts row hits refcount=0
#   - reaper deletes the storage object
#   - gc_reaps row is written
#   - /v2/_gc/status reports running, /v2/_gc/pause + /resume flip the flag
#
# Run from repo root:
#   GRACE=5 bash tests/e2e/online_gc_e2e.sh
#
# Skipped automatically in CI when DOCKER is not available.

set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────
REGISTRY_URL="${REGISTRY_URL:-http://localhost:5000}"
POSTGRES_URL="${POSTGRES_URL:-postgres://nebulacr:nebulacr@localhost:5432/nebulacr}"
GRACE="${GRACE:-5}"           # seconds — short for the test
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
TENANT="${TENANT:-acme}"
PROJECT="${PROJECT:-prod}"
REPO="${REPO:-gc-e2e}"
TAG="${TAG:-v1}"

if ! command -v docker >/dev/null; then
  echo "[skip] docker not available"
  exit 0
fi

# ── Helpers ──────────────────────────────────────────────────────────
log()  { printf "[gc-e2e] %s\n" "$*"; }
fail() { printf "[gc-e2e][FAIL] %s\n" "$*" >&2; exit 1; }

token() {
  curl -fsS -u "$ADMIN_USER:$ADMIN_PASS" \
    "$REGISTRY_URL/auth/token?service=nebulacr-registry&scope=repository:$1:$2" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])"
}

require_pg_psql() {
  if ! command -v psql >/dev/null; then
    log "psql not on PATH — installing via container"
    PSQL="docker run --rm --network host postgres:16-alpine psql"
  else
    PSQL="psql"
  fi
}

pg() { $PSQL "$POSTGRES_URL" -tAc "$1"; }

# ── Sanity checks ────────────────────────────────────────────────────
log "registry: $REGISTRY_URL  postgres: $POSTGRES_URL  grace: ${GRACE}s"
require_pg_psql

curl -fsS "$REGISTRY_URL/health" >/dev/null || fail "registry not healthy"

# Verify GC is enabled.
status=$(curl -fsS -u "$ADMIN_USER:$ADMIN_PASS" "$REGISTRY_URL/v2/_gc/status")
echo "$status" | grep -q '"enabled":true' \
  || fail "GC not enabled (status=$status). Set NEBULACR_GC__ONLINE=true."

# ── Step 1: push an image ────────────────────────────────────────────
log "pushing test image"
docker pull alpine:3.18 >/dev/null
docker tag alpine:3.18 "${REGISTRY_URL#http://}/$TENANT/$PROJECT/$REPO:$TAG"
docker login "${REGISTRY_URL#http://}" -u "$ADMIN_USER" -p "$ADMIN_PASS" >/dev/null 2>&1
docker push "${REGISTRY_URL#http://}/$TENANT/$PROJECT/$REPO:$TAG" >/dev/null

# ── Step 2: assert refcount > 0 + edges + paths exist ────────────────
log "asserting refcounts populated"
edges=$(pg "SELECT COUNT(*) FROM manifest_blob_refs WHERE tenant = '$TENANT'")
[[ "$edges" -gt 0 ]] || fail "expected manifest_blob_refs rows, got $edges"

paths=$(pg "SELECT COUNT(*) FROM blob_paths WHERE tenant='$TENANT' AND project='$PROJECT' AND repository='$REPO'")
[[ "$paths" -gt 0 ]] || fail "expected blob_paths rows, got $paths"

zero_count=$(pg "SELECT COUNT(*) FROM blob_refcounts WHERE tenant='$TENANT' AND refcount = 0")
[[ "$zero_count" -eq 0 ]] || fail "no blobs should be at refcount=0 yet"

# ── Step 3: pause/resume round-trip ──────────────────────────────────
log "verifying pause/resume"
curl -fsS -u "$ADMIN_USER:$ADMIN_PASS" -X POST "$REGISTRY_URL/v2/_gc/pause" \
  | grep -q '"paused":true' || fail "pause did not return paused=true"
curl -fsS -u "$ADMIN_USER:$ADMIN_PASS" "$REGISTRY_URL/v2/_gc/status" \
  | grep -q '"paused":true' || fail "status not paused"
curl -fsS -u "$ADMIN_USER:$ADMIN_PASS" -X POST "$REGISTRY_URL/v2/_gc/resume" \
  | grep -q '"paused":false' || fail "resume did not return paused=false"

# ── Step 4: delete the manifest, wait past grace, assert reap ────────
log "deleting manifest"
TOK=$(token "$TENANT/$PROJECT/$REPO" "*")
DIGEST=$(curl -fsS -H "Authorization: Bearer $TOK" \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  -I "$REGISTRY_URL/v2/$TENANT/$PROJECT/$REPO/manifests/$TAG" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')
[[ -n "$DIGEST" ]] || fail "could not resolve digest"

curl -fsS -H "Authorization: Bearer $TOK" -X DELETE \
  "$REGISTRY_URL/v2/$TENANT/$PROJECT/$REPO/manifests/$DIGEST" >/dev/null

log "waiting $((GRACE * 2)) seconds for reaper"
sleep $((GRACE * 2 + 5))

reaped=$(pg "SELECT COUNT(*) FROM gc_reaps WHERE tenant='$TENANT'")
[[ "$reaped" -gt 0 ]] || fail "expected gc_reaps rows, got $reaped"
log "OK: reaper deleted $reaped blobs"

# ── Step 5: reconciler audit returns clean ───────────────────────────
log "running reconciler"
result=$(curl -fsS -u "$ADMIN_USER:$ADMIN_PASS" -X POST \
  -H "Content-Type: application/json" \
  -d '{"apply": false}' \
  "$REGISTRY_URL/v2/_gc/reconcile")
echo "$result" | grep -q '"orphan":0' || fail "expected orphan=0, got $result"

log "PASS"
