# CI/CD integration

NebulaCR's scanner exposes a live endpoint that any CI system can poll after
pushing an image. Callers authenticate with a scanner API key and either pass
or fail the build based on the policy verdict.

## 1. Mint an API key

Keys are opaque `nck_*` strings; only a SHA-256 hash is stored server-side, so
the raw value is shown **exactly once** at creation time.

```bash
# Admin bootstrap — while legacy "system" access is still permissive,
# you can create the first CI key unauthenticated. Disable this as
# soon as you have the first admin key.
curl -s -X POST https://nebulacr.example.com/admin/scanner-keys \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ci-main",
    "tenant": "acme",
    "permissions": ["scan:read", "policy:evaluate"]
  }' | jq .
```

The response includes a `key` field — store it as a CI secret (e.g.
`NEBULACR_SCAN_KEY` in GitHub/GitLab). You won't be able to retrieve it again.

### Permission grants

| Permission         | Grants                                               |
|--------------------|------------------------------------------------------|
| `scan:read`        | `GET /v2/scan/live/{digest}`, CVE search, settings read |
| `scan:write`       | `POST /v2/scan` (re-queue a digest)                  |
| `policy:evaluate`  | `POST /v2/policy/evaluate`                           |
| `cve:search`       | `GET /v2/cve/search`                                 |
| `cve:suppress`     | create/revoke suppressions                           |
| `settings:write`   | `PATCH /v2/image/.../settings`                       |
| `admin`            | everything above + API key CRUD + ingest triggers    |

A CI pipeline usually only needs `scan:read` + `policy:evaluate`.

## 2. Poll the live scan endpoint

```bash
#!/usr/bin/env bash
# gate-on-scan.sh — fails the build when the policy verdict is not PASS.
set -euo pipefail

: "${NEBULACR_URL:?set to https://nebulacr.example.com}"
: "${NEBULACR_SCAN_KEY:?export from CI secret}"
: "${IMAGE_DIGEST:?sha256:...}"

deadline=$(( $(date +%s) + 600 ))  # 10 min budget

while :; do
  body=$(curl -sS --fail \
    -H "Authorization: Bearer ${NEBULACR_SCAN_KEY}" \
    "${NEBULACR_URL}/v2/scan/live/${IMAGE_DIGEST}")
  status=$(echo "$body" | jq -r '.status')

  case "$status" in
    completed)
      verdict=$(echo "$body" | jq -r '.result.policy_evaluation.status // "UNKNOWN"')
      echo "scan complete: $verdict"
      [[ "$verdict" == "PASS" ]] || { echo "$body" | jq '.result.summary'; exit 1; }
      exit 0
      ;;
    queued|in_progress)
      [[ $(date +%s) -lt $deadline ]] || { echo "scan timeout" >&2; exit 2; }
      sleep 5
      ;;
    failed|not_found)
      echo "scan $status" >&2
      exit 3
      ;;
    *)
      echo "unexpected status $status" >&2
      exit 4
      ;;
  esac
done
```

Usage:

```bash
DIGEST=$(docker buildx imagetools inspect --raw $IMAGE | sha256sum | awk '{print "sha256:"$1}')
IMAGE_DIGEST=$DIGEST bash gate-on-scan.sh
```

## 3. GitHub Actions

```yaml
name: build-scan-deploy
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: docker/login-action@v3
        with:
          registry: nebulacr.example.com
          username: ${{ secrets.NEBULACR_USER }}
          password: ${{ secrets.NEBULACR_PASS }}

      - id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: nebulacr.example.com/acme/web/api:${{ github.sha }}

      - name: Wait for scan verdict
        env:
          NEBULACR_URL: https://nebulacr.example.com
          NEBULACR_SCAN_KEY: ${{ secrets.NEBULACR_SCAN_KEY }}
          IMAGE_DIGEST: ${{ steps.build.outputs.digest }}
        run: bash docs/examples/gate-on-scan.sh

      - name: Deploy
        run: ./deploy.sh ${{ steps.build.outputs.digest }}
```

## 4. GitLab CI

```yaml
scan-gate:
  stage: verify
  needs: [build-and-push]
  image: alpine:3.20
  before_script:
    - apk add --no-cache curl jq bash
  script:
    - NEBULACR_URL=https://nebulacr.example.com
    - export IMAGE_DIGEST=$BUILD_DIGEST
    - bash docs/examples/gate-on-scan.sh
  variables:
    NEBULACR_SCAN_KEY: $NEBULACR_SCAN_KEY   # masked variable
```

## 5. Rotate or revoke a key

```bash
# list active keys
curl -H "Authorization: Bearer $ADMIN_KEY" \
  https://nebulacr.example.com/admin/scanner-keys | jq .

# revoke by id
curl -X DELETE -H "Authorization: Bearer $ADMIN_KEY" \
  https://nebulacr.example.com/admin/scanner-keys/$KEY_ID
```

Revoked keys immediately fail lookup (the unique index on `key_hash` is
partial on `revoked_at IS NULL`).
