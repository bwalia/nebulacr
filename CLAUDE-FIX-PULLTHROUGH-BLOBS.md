# Fix: Pull-through cache must proxy blobs, not just manifests

## Problem

NebulaCR's pull-through cache currently fetches and caches **manifests** from upstream registries (Docker Hub, GHCR, etc.) but does NOT fetch the **blobs** (layers, config). When Docker pulls an image through the cache:

1. GET manifest -> registry fetches from upstream, caches locally, returns to Docker (WORKS)
2. GET blob (layer) -> registry checks local storage, blob not found, returns 404 (BROKEN)

Docker then fails with:
```
error from registry: storage error: Object at location
/var/lib/nebulacr/data/_/library/alpine/manifests/sha256:... not found
```

## Root Cause

The `get_manifest` handler in `crates/nebula-registry/src/main.rs` correctly falls through to the mirror service on local miss (fixed in commit 71086e8). The mirror service fetches the manifest from upstream and caches it locally.

However, the `get_blob` handler at line ~933 only tries the mirror fallback when `state.store.get()` fails. The blob path is constructed correctly, but when the blob doesn't exist locally, the mirror's `fetch_blob` method is called. The issue is one of two things:

### Scenario A: fetch_blob doesn't download the actual blob data
The `MirrorService::fetch_blob()` in `crates/nebula-mirror/src/service.rs:173` may not be correctly downloading and storing the blob from the upstream registry.

### Scenario B: The blob path doesn't match
The manifest references blobs by digest (e.g., `sha256:abc123`), but the blob storage path uses `blob_path(tenant, project, name, digest)`. For pull-through cached images, the tenant is `_` (default), project is `library`, name is `alpine`. The upstream blob might be stored at a different path than what the manifest references.

### Scenario C: HEAD blob returns 404 before GET blob tries mirror
Docker first sends HEAD requests to check blob existence. The `head_blob` handler does NOT have mirror fallback — it only checks local storage. If HEAD returns 404, Docker may skip the blob entirely instead of trying GET.

## What Has Been Tried

- Adding mirror fallback to `head_manifest` and `head_blob` caused ALL locally-pushed
  images to trigger slow upstream lookups (5 registries tried sequentially) on every
  pull, breaking push-pull round trips. This was reverted in commit ccb02b3.
- The `get_manifest` handler correctly falls through to mirror on local miss (commit 71086e8).
- The `get_blob` handler already has mirror fallback and `fetch_blob` correctly downloads
  and caches blobs from upstream.

## What Actually Needs to Be Fixed

### The Core Problem: Docker sends HEAD before GET for pull-through

Docker's pull flow: HEAD manifest -> if 404, give up (does NOT try GET).
The `head_manifest` handler only checks local storage. For pull-through images that
haven't been cached yet, HEAD returns 404 and Docker stops.

### Fix Option A: Smart HEAD fallback (RECOMMENDED)

Add mirror fallback to `head_manifest` and `head_blob` BUT only for paths that
look like upstream images. Use the mirror service's `resolve_upstreams(tenant)` to
check if the tenant has any upstream routing. For the default tenant `_`, check if
the project name matches a known upstream registry prefix (e.g., `library`, `docker.io`).

For locally-pushed images (tenant `demo`, `_` with custom project names), skip mirror.

### Fix Option B: Pre-fetch on GET manifest

When `get_manifest` fetches a manifest from upstream, parse it and pre-fetch all
referenced blobs in the background. This way when Docker subsequently requests blobs
via HEAD, they're already cached locally.

### Fix Option C: Transparent proxy mode

Instead of returning 404 on HEAD miss, return a redirect (307) to the upstream
registry. Docker will follow the redirect and pull directly. This avoids caching
but makes pull-through work immediately.

### 4. Handle manifest-list/index responses

When Docker pulls a multi-arch image, the first manifest returned is often a manifest
list (index). The registry needs to:
- Cache the manifest list
- When Docker requests a platform-specific manifest (by digest from the list), also
  proxy that from upstream
- Then proxy the blobs referenced by the platform-specific manifest

## Key Files

- `crates/nebula-registry/src/main.rs` — `head_blob` (~782), `get_blob` (~900), `get_manifest` (~487)
- `crates/nebula-mirror/src/service.rs` — `fetch_manifest` (78), `fetch_blob` (173)
- `crates/nebula-mirror/src/upstream.rs` — `get_manifest` (142), `get_blob` (actual HTTP fetch)
- `crates/nebula-common/src/storage.rs` — `blob_path`, `manifest_path` helpers

## How to Test

```bash
# 1. Trigger nightly test (includes pull-through cache tests)
gh workflow run "Nightly Registry Health Test"

# 2. Manual test from inside k3s cluster
kubectl exec -n github-runners deploy/gh-runner-nebulacr -c runner -- bash -c '
  docker pull nebulacr-registry.acc.svc.cluster.local:5000/library/alpine:3.20
'

# 3. Verify with curl (step by step)
TOKEN=$(curl -sf -u admin:admin "http://nebulacr-auth:5001/auth/token?service=nebulacr-registry&scope=repository:library/alpine:pull" | jq -r .token)

# Get manifest (should proxy from Docker Hub)
curl -sf "http://nebulacr-registry:5000/v2/library/alpine/manifests/3.20" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" | jq .

# Get a specific blob (should also proxy)
curl -sf "http://nebulacr-registry:5000/v2/library/alpine/blobs/sha256:<digest>" \
  -H "Authorization: Bearer $TOKEN" -o /dev/null -w "%{http_code}"
```

## Current Test Results (16/20 passing)

Passing:
- Auth (primary + mirror), Health (primary + mirror), V2 API, Dashboard
- HA status, Metrics (sometimes)
- Push 3-seg, Image status API, Pull 3-seg, Verify image
- Push 2-seg, Pull 2-seg
- Catalog API, Tag listing, Mirror replication

Failing:
- Pull-through cache: alpine (manifest cached but blobs 404)
- Pull-through cache: large image / wslproxy (same issue)
- Pull-through cache: verify cached (skipped because first pull fails)

## Deployed Environment

- Primary registry: `nebulacr-registry.acc.svc.cluster.local:5000` (k3s0 cluster)
- Auth service: `nebulacr-auth.acc.svc.cluster.local:5001`
- Mirror: `187.77.179.206:5050` (native systemd)
- Internal DinD runner: `github-runners` namespace, pod `gh-runner-nebulacr`
- Storage: filesystem PVC at `/var/lib/nebulacr/data` on node `debian001`
