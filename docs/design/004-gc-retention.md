# 004 — Reference-Counted Garbage Collection + Retention Policies

> **Summary.** Two cooperating systems. **GC** is a mark-and-sweep over
> blobs and manifests using reference counts (manifests → blobs, tags →
> manifests). **Retention** is a per-Project policy (the
> `RetentionPolicy` struct already exists at
> `crates/nebula-controller/src/main.rs:88`) that deletes tags older
> than D days, beyond N most recent, or matching a regex. Both run as
> controller-managed jobs with grace periods to avoid racing in-flight
> uploads.

## a. Problem statement

ACR has `az acr run --cmd 'acr purge'` and Nexus has cleanup policies.
NebulaCR has a `RetentionPolicy` field on the Project CRD with no
implementation behind it. Storage usage grows monotonically forever.
This is the most-requested operational feature for any registry past
six months in production.

## b. Proposed approach

New crate `nebula-gc` (or module under `nebula-controller`; pick
controller for now — it has the kube client wired up). Two services:

```rust
// crates/nebula-controller/src/gc/mod.rs
pub struct GcRunner { store: Arc<dyn ObjectStore>, db: PgPool }

impl GcRunner {
    /// Mark phase. Walks tag links → manifests → blob descriptors and
    /// records every reachable digest in `gc_marks(run_id, digest)`.
    pub async fn mark(&self, run_id: Uuid) -> Result<MarkStats, Err>;

    /// Sweep phase. Lists all blobs/manifests in storage, deletes any
    /// not in `gc_marks(run_id)` AND older than `grace_period`.
    pub async fn sweep(&self, run_id: Uuid) -> Result<SweepStats, Err>;
}

pub struct RetentionRunner { db: PgPool, registry: HttpClient }

impl RetentionRunner {
    /// Apply a project's retention policy: build the keep-set, delete
    /// the rest by calling DELETE /v2/.../manifests/{tag} which (with
    /// 003 active) transitions the tag through the state machine.
    pub async fn apply(&self, project: &ProjectRef) -> Result<RetentionReport, Err>;
}
```

Critical invariant: **upload sessions register themselves**. The
existing `initiate_blob_upload` at
`crates/nebula-registry/src/main.rs:1338` writes a row to a new
`pending_uploads` table on start. The sweep ignores any blob whose
digest matches an unfinished upload OR whose mtime is within
`grace_period` (default 24 h). This solves the in-flight race without
distributed locks.

The mark phase is the only place that walks manifest JSON to extract
blob descriptors; reuse `nebula_common::models::Manifest`
(`crates/nebula-common/src/models.rs:55`).

Retention rules per project (CRD additions on top of the existing
`RetentionPolicy`):

```yaml
retentionPolicy:
  maxTagCount: 50            # already exists
  expireDays: 90             # already exists
  keepRegex: '^v\d+\.\d+\.\d+$'    # NEW — keep semver tags forever
  alwaysKeep: ["latest", "stable"] # NEW — never delete these
  dryRun: false              # NEW — log what would delete, do nothing
```

Schedule: a `Kubernetes CronJob` provisioned by the controller per
tenant. GC runs nightly at a tenant-randomised UTC hour; retention
runs hourly.

CLI: `nebulacr gc run [--dry-run]`, `nebulacr gc status`,
`nebulacr retention apply --project acme/prod`. MCP: `start_gc_run`,
`get_gc_status`.

## c. New/changed CRDs

Project CRD extension only; no new CRD:

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Project
metadata:
  name: prod
spec:
  tenantRef: acme
  retentionPolicy:
    maxTagCount: 50
    expireDays: 90
    keepRegex: '^v\d+\.\d+\.\d+$'
    alwaysKeep: ["latest", "stable"]
    dryRun: false
  gc:
    enabled: true
    schedule: "0 3 * * *"            # cron, controller-rendered to CronJob
    gracePeriodHours: 24
```

## d. New HTTP routes

| Method | Path                                                       | Auth scope         | Notes                                          |
| ------ | ---------------------------------------------------------- | ------------------ | ---------------------------------------------- |
| POST   | `/v2/_gc/runs`                                             | `tenant:admin`     | Body `{dryRun}` → 202 with run UUID            |
| GET    | `/v2/_gc/runs/{id}`                                        | `tenant:admin`     | Status + stats                                 |
| GET    | `/v2/_gc/runs`                                             | `tenant:admin`     | List recent runs, paged                        |
| POST   | `/v2/_retention/apply`                                     | `tenant:admin`     | Body `{tenant, project}` → run report          |

The internal mark/sweep is invoked by the controller's CronJob calling
`POST /v2/_gc/runs` with a service-account token; it's not a separate
binary.

## e. Storage / Postgres schema

```sql
-- 0007_gc_retention.sql
CREATE TABLE gc_runs (
    id           UUID PRIMARY KEY,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at  TIMESTAMPTZ,
    phase        TEXT NOT NULL,                  -- 'marking' | 'sweeping' | 'done' | 'failed'
    blobs_marked BIGINT NOT NULL DEFAULT 0,
    blobs_swept  BIGINT NOT NULL DEFAULT 0,
    bytes_freed  BIGINT NOT NULL DEFAULT 0,
    error        TEXT,
    dry_run      BOOLEAN NOT NULL DEFAULT FALSE
);

-- Ephemeral mark set; scoped to a single run, truncated after sweep.
CREATE UNLOGGED TABLE gc_marks (
    run_id       UUID NOT NULL REFERENCES gc_runs(id) ON DELETE CASCADE,
    digest       TEXT NOT NULL,
    PRIMARY KEY (run_id, digest)
);

CREATE TABLE pending_uploads (
    upload_id    UUID PRIMARY KEY,
    tenant       TEXT NOT NULL,
    project      TEXT NOT NULL,
    repository   TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_chunk_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX pending_uploads_started_idx ON pending_uploads (started_at);

CREATE TABLE retention_runs (
    id           UUID PRIMARY KEY,
    tenant       TEXT NOT NULL,
    project      TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags_kept    INT NOT NULL DEFAULT 0,
    tags_deleted INT NOT NULL DEFAULT 0,
    dry_run      BOOLEAN NOT NULL DEFAULT FALSE
);
```

`gc_marks` as `UNLOGGED` is intentional — it's recomputable and writes
are heavy.

## f. Failure modes

- **Mark crashes.** Run row stays in `marking`. A controller sweeper
  marks it `failed` after `2 × max_run_duration`. Sweep never runs on
  a failed mark — invariant.
- **Sweep deletes a blob still being referenced.** Cannot happen if
  invariant 1 (mark before sweep) and invariant 2 (grace period >
  longest-acceptable-upload-duration) both hold. Both are enforced in
  the runner; the grace period is configurable per-project.
- **Storage backend rate-limits the sweep.** Sweep paces itself via a
  configurable token bucket (`sweep_qps`); on 429 it backs off 30 s
  and resumes from the cursor.
- **Retention deletes a tag that's still in `Promoted` state.** Block
  via `Project.gc.respectPromotion: true` (default true) — promoted
  tags are excluded from delete-set.

## g. Migration story

`[gc]` section, `enabled = false`. The schema ships, the CronJobs are
not provisioned. Existing deployments are unaffected. Operators
enable per-tenant. First-run on a large existing registry is
expensive (full bucket walk); the runner streams the listing to bound
memory.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Mark walker        | `crates/nebula-controller/tests/gc_mark.rs`            | In-memory `ObjectStore`, fake manifests     |
| Sweep grace period | `crates/nebula-controller/tests/gc_grace.rs`           | Asserts in-flight upload survives           |
| Retention regex    | `crates/nebula-controller/tests/retention_regex.rs`    | Postgres testcontainer, real CRD           |
| End-to-end         | `tests/e2e/gc_e2e.sh`                                  | Push 100 images, retain top 10, run GC      |
| Recovery           | `crates/nebula-controller/tests/gc_recovery.rs`        | Kill mid-mark; assert sweeper recovers      |

## i. Implementation slice count

4 slices, ~4 weeks:

1. Schema, `pending_uploads` registration in
   `initiate_blob_upload`/`upload_blob_chunk`/`complete_blob_upload`,
   and the dry-run mark phase only.
2. Sweep phase with grace period + run-state machine + retry/backoff.
3. Retention runner: regex / count / age / alwaysKeep, integration
   with tag-state (003) so retention deletes flow through transitions.
4. Controller CronJob templates + Helm values + CLI + e2e + docs.
