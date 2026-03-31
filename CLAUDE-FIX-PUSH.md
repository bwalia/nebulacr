# Fix: Docker push returns 404/502 on blob upload — NebulaCR registry

## Problem

`docker push acc-nebulacr.diytaxreturn.co.uk/diytaxreturn/diy-tax-return-uk:latest` fails with:

```
unknown: unexpected status from POST request to
https://acc-nebulacr.diytaxreturn.co.uk/v2/diytaxreturn/diy-tax-return-uk/blobs/uploads/: 404 Not Found
```

The CI test at https://github.com/bwalia/nebulacr/actions/runs/23726139273/job/69109983909 also fails with `502 Bad Gateway` on the same endpoint.

## Root Cause

NebulaCR routes expect **3 path segments** (`{tenant}/{project}/{name}`):

```rust
// crates/nebula-registry/src/main.rs line 2091
"/v2/{tenant}/{project}/{name}/blobs/uploads/"
```

But standard Docker clients push with **2 segments** (`{namespace}/{repo}`):

```
POST /v2/diytaxreturn/diy-tax-return-uk/blobs/uploads/
```

This doesn't match the 3-segment route, so axum returns 404 (no route matched).

The CI test uses 3 segments (`demo/default/nightly-test`) which matches the route — but that test gets a 502, likely because the auth service or storage isn't configured correctly in the CI environment.

## What Needs to Be Fixed

### 1. Support 2-segment Docker image paths via default tenant (CRITICAL)

Standard Docker registries use `{namespace}/{repo}` (2 segments), but NebulaCR uses `{tenant}/{project}/{name}` (3 segments) for multi-tenancy. Both must work.

Add middleware or duplicate routes that rewrite 2-segment paths into 3-segment paths using a **default tenant** (e.g., `_` or `library`). When a user pushes to:

```
docker push registry/diytaxreturn/diy-tax-return-uk:latest
```

The registry should treat this as `_/diytaxreturn/diy-tax-return-uk` (default tenant, namespace=project, repo=name). This way:
- 3-segment paths continue to work for multi-tenant users
- 2-segment paths work for standard Docker workflows via the default tenant

All affected routes in `main.rs` (around lines 2060-2106):
- `/v2/{tenant}/{project}/{name}/manifests/{reference}` (GET, HEAD, PUT, DELETE)
- `/v2/{tenant}/{project}/{name}/blobs/{digest}` (HEAD, GET)
- `/v2/{tenant}/{project}/{name}/blobs/uploads/` (POST)
- `/v2/{tenant}/{project}/{name}/blobs/uploads/{uuid}` (PATCH, PUT)
- `/v2/{tenant}/{project}/{name}/status/{reference}` (GET)
- `/v2/{tenant}/{project}/{name}/tags/list` (GET)

Need corresponding 2-segment routes:
- `/v2/{project}/{name}/manifests/{reference}`
- `/v2/{project}/{name}/blobs/{digest}`
- `/v2/{project}/{name}/blobs/uploads/`
- `/v2/{project}/{name}/blobs/uploads/{uuid}`
- `/v2/{project}/{name}/status/{reference}`
- `/v2/{project}/{name}/tags/list`

These should internally map to `tenant = "_"` (or a configurable default tenant) and call the same handler functions.

### 2. Fix the CI test (Registry Health Test job)

The CI test pushes to `demo/default/nightly-test` (3 segments) but gets `502 Bad Gateway`. This suggests the auth service isn't reachable or isn't issuing valid tokens in the CI environment. Check:

- Is the auth service (`nebula-auth`) starting and healthy in CI?
- Is the JWT signing key configured correctly?
- Is the `authorize()` call in `initiate_blob_upload` (line 891) failing and returning an error that gets mapped to 502?

### 3. Verify the full push flow works end-to-end

After fixing, verify these Docker commands work:

```bash
docker login acc-nebulacr.diytaxreturn.co.uk -u admin -p admin

# 2-segment (standard Docker — uses default tenant automatically)
docker tag alpine:latest acc-nebulacr.diytaxreturn.co.uk/diytaxreturn/diy-tax-return-uk:latest
docker push acc-nebulacr.diytaxreturn.co.uk/diytaxreturn/diy-tax-return-uk:latest
# Should internally store under tenant "_" (default), project "diytaxreturn", name "diy-tax-return-uk"

# 3-segment (NebulaCR multi-tenant — explicit tenant)
docker tag alpine:latest acc-nebulacr.diytaxreturn.co.uk/mytenant/myproject/myapp:latest
docker push acc-nebulacr.diytaxreturn.co.uk/mytenant/myproject/myapp:latest
# Uses tenant "mytenant", project "myproject", name "myapp"
```

## Key Files

- `crates/nebula-registry/src/main.rs` — Route definitions (line ~2060-2106) and handler functions (`initiate_blob_upload` at line 886, `upload_blob_chunk` at line 933, `complete_blob_upload` at line 999)
- `crates/nebula-auth/` — Auth service that issues JWT tokens
- `crates/nebula-common/` — Shared types including `RepoPath`, `StorePath`
- `.github/workflows/` — CI workflow with "Registry Health Test" job
- `deploy/` — Helm chart and deployment manifests

## Deployed Environment

- Registry: `acc-nebulacr.diytaxreturn.co.uk` (K3s cluster, namespace `acc`)
- Auth: `admin:admin` (basic auth)
- Helm release: `nebulacr` v0.3.0, revision 20
- Storage: filesystem PVC at `/var/lib/nebulacr/data`
