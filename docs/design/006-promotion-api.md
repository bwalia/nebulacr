# 006 — Atomic Promotion API

> **Summary.** `POST /v2/_promote` copies a manifest, every blob it
> references, and every signature attached to it from a source
> `(tenant, project, repo, tag)` to a destination, atomically. When
> source and dest share a storage backend it's a metadata-only retag;
> across backends it's a streamed copy. Signatures (001) are preserved.
> Audit row (005) records the operation. An optional
> `promote-on-policy-pass` mode wires it into the admission gate (002).

## a. Problem statement

ACR has `az acr import`; Nexus has the staging-promote workflow. To
move an image from `dev/foo:1.2.3` to `prod/foo:1.2.3` today, you have
to pull and push, breaking the digest chain and losing signatures.
Promotion is the canonical SDLC primitive for separating dev/staging/
prod registries; without it teams either skip separation or run
multiple registries.

## b. Proposed approach

New module `crates/nebula-registry/src/promote.rs`. The single entry:

```rust
pub struct PromoteRequest {
    pub source: ImageRef,           // {tenant, project, repo, ref}
    pub dest:   ImageRef,
    pub include_signatures: bool,   // default true
    pub include_attestations: bool, // default true
    pub mode: PromoteMode,
}

pub enum PromoteMode {
    Force,
    OnPolicyPass { policy: String },  // requires 002
    DryRun,
}

pub async fn promote(state: &AppState, req: &PromoteRequest, claims: &TokenClaims)
    -> Result<PromoteOutcome, RegistryError>;
```

Flow:

1. Authorise `pull` on source, `push` on dest.
2. Resolve source manifest digest (use `resolve_manifest_path` at
   `crates/nebula-registry/src/main.rs:1718`).
3. If dest project has `immutable_tags = true` and dest tag exists with
   different digest → 409 (delegate to 003's check).
4. Same-backend short-circuit: if `state.store` source path and dest
   path share a bucket, `object_store::copy` (one syscall on S3, file
   rename on filesystem). Update the tag link only.
5. Cross-backend: stream blob list from manifest descriptors, for each
   missing dest blob `dst.put(stream)`. Then put manifest, then put
   tag link.
6. Discover signatures via the OCI 1.1 referrers index at
   `sha256-<digest>.sig`; promote each as a normal manifest.
7. **Atomicity**: write all blobs first, then manifest, then tag link
   last. If anything fails before the tag link write, dest digest is
   addressable but not tagged — safe (will be GC'd by 004 after grace).
8. Insert `tag_records` row at dest with state `Promoted` (003).
9. Insert audit row category=`Promote` with source+dest digests.

`OnPolicyPass` mode evaluates the dest project's `AdmissionPolicy`
(002) against the source digest's scan result; on pass, proceeds; on
fail, returns a structured error with the policy violations.

CLI: `nebulacr promote acme/dev/api:1.2.3 acme/prod/api:1.2.3
[--policy prod-block-criticals]`. MCP: `promote_image`, `dry_run_promote`.

## c. New/changed CRDs

No new CRD. Optional new field on `Project.spec` (additive):

```yaml
spec:
  promotionTargets:
    - destProject: prod
      requirePolicy: prod-block-criticals
      requireSignedBy: vault://transit/cosign-acme-prod
```

If set, the controller can pre-validate the path; the runtime check
still happens on each promote call.

## d. New HTTP routes

| Method | Path                              | Auth scope                            | Notes                                          |
| ------ | --------------------------------- | ------------------------------------- | ---------------------------------------------- |
| POST   | `/v2/_promote`                    | `repo:pull` source + `repo:push` dest | Body = `PromoteRequest`; returns digest        |
| GET    | `/v2/_promote/{id}`               | `tenant:read`                         | Status of an async promotion                   |
| GET    | `/v2/_promote/history?repo=...`   | `repo:read`                           | List of past promotions for a repo             |

Cross-tenant promotion requires a token with both scopes — RBAC
existing model in `crates/nebula-registry/src/main.rs:170` covers
this naturally.

## e. Storage / Postgres schema

```sql
-- 0009_promotions.sql
CREATE TABLE promotions (
    id              UUID PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    actor           TEXT NOT NULL,
    src_tenant      TEXT NOT NULL,
    src_project     TEXT NOT NULL,
    src_repository  TEXT NOT NULL,
    src_reference   TEXT NOT NULL,
    src_digest      TEXT NOT NULL,
    dst_tenant      TEXT NOT NULL,
    dst_project     TEXT NOT NULL,
    dst_repository  TEXT NOT NULL,
    dst_reference   TEXT NOT NULL,
    state           TEXT NOT NULL,                 -- 'pending' | 'copying' | 'done' | 'failed'
    error           TEXT,
    bytes_copied    BIGINT NOT NULL DEFAULT 0,
    blob_count      INT NOT NULL DEFAULT 0,
    signatures_copied INT NOT NULL DEFAULT 0
);
CREATE INDEX promotions_dst_idx ON promotions (dst_tenant, dst_project, dst_repository, started_at DESC);
CREATE INDEX promotions_src_idx ON promotions (src_digest);
```

## f. Failure modes

- **Mid-promotion crash.** Tag link not yet written → dest is partially
  populated but not addressable by tag. GC sweeps it after grace
  (relies on 004). Caller sees 503, retries idempotently — same digest
  re-promote is a fast no-op because blobs already exist.
- **Dest immutability collision.** 409 with the existing-digest
  surfaced; caller decides to force-delete-then-promote (separate calls).
- **Source policy fails on `OnPolicyPass`.** 422 with the violations
  array, no state change.
- **Cross-region promotion.** Out of scope for v1 — explicitly require
  same-region. v1.1 wires `nebula_replication::Replicator` to do
  cross-region atomically.

## g. Migration story

`[promotion]` section, `enabled = false` ships the schema and routes
but routes return 404. Operators flip on per-tenant. No data migration —
new feature only acts on new calls.

## h. Test plan

| Layer            | Where                                                | Notes                                       |
| ---------------- | ---------------------------------------------------- | ------------------------------------------- |
| Same-backend     | `crates/nebula-registry/tests/promote_same.rs`       | Filesystem store, retag short-circuit       |
| Cross-backend    | `crates/nebula-registry/tests/promote_cross.rs`      | S3 + GCS testcontainers                     |
| With signatures  | `crates/nebula-registry/tests/promote_signed.rs`     | Push, sign, promote, verify dest sig        |
| OnPolicyPass     | `crates/nebula-registry/tests/promote_policy.rs`     | Mock scan result; pass and fail variants    |
| Crash recovery   | `crates/nebula-registry/tests/promote_recovery.rs`   | Inject fault mid-copy; idempotent retry     |

## i. Implementation slice count

3 slices, ~3 weeks:

1. Same-backend retag path + schema + `_promote` route + CLI.
2. Cross-backend streamed copy + signatures + immutability/quarantine
   integration.
3. `OnPolicyPass` mode + history endpoint + dashboard wiring.
