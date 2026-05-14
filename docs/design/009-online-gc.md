# 009 — Online Garbage Collection (Zero Read-Only Window)

> **Summary.** Replace the mark-and-sweep flow proposed in 004 with a
> live, reference-counted blob index maintained inside Postgres.
> Manifest writes/deletes mutate refcounts inside the same transaction
> that commits the manifest row; a continuous reaper deletes blobs
> whose refcount has been zero for longer than `grace_period`. Pushes
> and pulls never block on GC, and there is no read-only window.
> 004 stays as the periodic reconciler that fixes drift.

## a. Problem statement

Sonatype Nexus's GC is the single most-quoted operational pain in the
container-registry space: it requires the registry to be put into a
read-only mode (`docker registry garbage-collect`) for hours; large
deployments schedule it quarterly because the outage is expensive.
ACR hides GC behind a managed plane but customers cannot tune it,
trace it, or reason about reclaim latency. NebulaCR's planned 004
inherits the same mark-and-sweep idiom and will face the same scaling
wall once a tenant exceeds ~10 M blobs. We need GC that is **always
on** and never asks operators to choose between fresh writes and
reclaimed bytes.

## b. Proposed approach

New crate `nebula-gc` (graduated from the 004 controller module).
Two cooperating pieces:

```rust
// crates/nebula-gc/src/refcount.rs
#[async_trait]
pub trait BlobRefCounter: Send + Sync {
    /// Bumps refcount for every blob descriptor referenced by `manifest`.
    /// Idempotent on `(manifest_digest, blob_digest)`. Must run in the
    /// same tx as the manifest insert.
    async fn add_refs(&self, tx: &mut PgTx<'_>, manifest_digest: &Digest,
                     blob_digests: &[Digest]) -> Result<(), GcError>;

    /// Decrements refcounts when a manifest row is deleted.
    async fn remove_refs(&self, tx: &mut PgTx<'_>, manifest_digest: &Digest)
        -> Result<(), GcError>;
}

// crates/nebula-gc/src/reaper.rs
pub struct ContinuousReaper {
    pool: PgPool,
    store: Arc<dyn ObjectStore>,
    grace: Duration,        // default 24h
    rate: TokenBucket,      // sweep_qps from config
}

impl ContinuousReaper {
    /// Long-running task: SELECT … FROM blob_refcounts
    /// WHERE refcount = 0 AND zeroed_at < NOW() - $grace
    /// LIMIT 1000 FOR UPDATE SKIP LOCKED, then delete from store and
    /// from the table inside a tx.
    pub async fn run(self) -> Result<Infallible, GcError>;
}
```

The refcounter wires into three places only — every manifest mutation
goes through one of them:

- `put_manifest` at `crates/nebula-registry/src/main.rs:886` — parse the
  manifest body, call `add_refs(tx, manifest_digest, layer_descriptors)`.
- `delete_manifest` at `crates/nebula-registry/src/main.rs:1048` —
  `remove_refs(tx, manifest_digest)`.
- 006 promotion — copying a manifest into a target project also bumps
  refs in the destination tenant's bookkeeping (refcount table is
  tenant-scoped).

Because the refcount mutation lives in the same transaction as the
manifest write, **there is no race**: a partial commit either creates
the manifest with all its refs, or rolls back both. Pull is unaffected
— it doesn't touch the refcount table.

The reaper holds no global lock. `FOR UPDATE SKIP LOCKED` lets multiple
reaper instances coexist (HA registry), each draining a different
slice of the zero-refcount queue. The token bucket caps storage-side
delete QPS to keep S3 / GCS happy. On a 429 from the backend, the
worker backs off 30 s and resumes from the cursor.

The 004 reconciler is repurposed: it now runs weekly, walks every
manifest row, recomputes the expected refcount per blob, and
reconciles against `blob_refcounts`. Drift is logged as
`nebulacr_gc_drift_total{kind="orphan"|"missing"}` and corrected. This
catches bugs in the refcount writers and storage corruption alike.

`pending_uploads` from 004 is still required: the reaper additionally
filters out any digest whose mtime is younger than `grace` *or* whose
ID matches an unfinished upload session. This guards the
push-but-don't-yet-finalise window.

CLI: `nebulacr gc status` (queue depth, recent reaps, drift count),
`nebulacr gc pause` / `nebulacr gc resume` (sets a flag the reaper
checks each cycle), `nebulacr gc reconcile --tenant acme --dry-run`
(invokes the 004 reconciler ad-hoc). MCP: `gc_status`, `gc_pause`,
`gc_reconcile`.

## c. New/changed CRDs

The `Project.spec.gc` block from 004 gains one field; no new CRD:

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Project
metadata:
  name: prod
spec:
  tenantRef: acme
  gc:
    enabled: true              # 004
    schedule: "0 3 * * *"      # 004 — now applies to reconciler only
    gracePeriodHours: 24       # 004 — applies to reaper
    onlineReap: true           # NEW — reaper runs continuously
    sweepQps: 100              # NEW — per-reaper-instance cap
```

`onlineReap: false` falls back to the 004 mark-and-sweep behaviour for
operators who want the old shape.

## d. New HTTP routes

| Method | Path                                                       | Auth scope         | Notes                                          |
| ------ | ---------------------------------------------------------- | ------------------ | ---------------------------------------------- |
| GET    | `/v2/_gc/status`                                           | `tenant:admin`     | Queue depth, reap rate, drift counters         |
| POST   | `/v2/_gc/pause`                                            | `tenant:admin`     | Pause reaper; idempotent                       |
| POST   | `/v2/_gc/resume`                                           | `tenant:admin`     | Resume reaper                                  |
| POST   | `/v2/_gc/reconcile`                                        | `tenant:admin`     | Body `{tenant, dryRun}` → reconcile run id     |
| GET    | `/v2/_gc/reconcile/{id}`                                   | `tenant:admin`     | Reconcile result                               |

The 004 routes (`POST /v2/_gc/runs`, …) remain — they now drive the
reconciler, not the live reaper.

## e. Storage / Postgres schema

```sql
-- 0009_online_gc.sql

-- Live refcount table. Composite PK avoids per-blob row churn when
-- the same blob is referenced by many manifests.
CREATE TABLE blob_refcounts (
    tenant         TEXT NOT NULL,
    blob_digest    TEXT NOT NULL,
    refcount       BIGINT NOT NULL DEFAULT 0,
    zeroed_at      TIMESTAMPTZ,                    -- set when refcount → 0
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bytes          BIGINT NOT NULL,                -- cached for reaper stats
    PRIMARY KEY (tenant, blob_digest)
);

-- Partial index: the reaper's hot path query.
CREATE INDEX blob_refcounts_zero_idx
    ON blob_refcounts (tenant, zeroed_at)
    WHERE refcount = 0;

-- Manifest → blob edges. Lets us recompute refcounts during
-- reconciliation and remove_refs without re-parsing the manifest.
CREATE TABLE manifest_blob_refs (
    tenant            TEXT NOT NULL,
    manifest_digest   TEXT NOT NULL,
    blob_digest       TEXT NOT NULL,
    PRIMARY KEY (tenant, manifest_digest, blob_digest)
);
CREATE INDEX manifest_blob_refs_blob_idx
    ON manifest_blob_refs (tenant, blob_digest);

-- Reaper bookkeeping: every reap is auditable.
CREATE TABLE gc_reaps (
    id            BIGSERIAL PRIMARY KEY,
    tenant        TEXT NOT NULL,
    blob_digest   TEXT NOT NULL,
    bytes_freed   BIGINT NOT NULL,
    reaped_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reconciler    BOOLEAN NOT NULL DEFAULT FALSE   -- TRUE if 004 path
);
CREATE INDEX gc_reaps_at_idx ON gc_reaps (reaped_at DESC);

-- Reconciler drift log.
CREATE TABLE gc_drift (
    id            BIGSERIAL PRIMARY KEY,
    tenant        TEXT NOT NULL,
    blob_digest   TEXT NOT NULL,
    kind          TEXT NOT NULL,                   -- 'orphan' | 'missing'
    expected      BIGINT NOT NULL,
    observed      BIGINT NOT NULL,
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    corrected_at  TIMESTAMPTZ
);
```

`blob_refcounts` is the only hot-write table. With 1k pushes/sec
and ~30 layers/manifest the steady-state insert rate is ~30k
row-touches/sec, which Postgres handles trivially with the partial
index.

## f. Failure modes

- **Refcount write succeeds, manifest write fails.** Impossible — they
  share a transaction. The Postgres error rolls both back.
- **Reaper deletes a blob that a concurrent push references.** Cannot
  happen. The push's `add_refs` flips `refcount` from 0 to 1 inside a
  tx that also clears `zeroed_at`; the reaper's `SELECT … WHERE
  refcount = 0 AND zeroed_at < NOW() - grace` excludes it. The grace
  period bounds the worst case where a client pushes a layer, gets a
  202 for the upload session, then takes >grace to finalise the
  manifest — `pending_uploads` covers that gap.
- **Refcount underflow.** Defensive `CHECK (refcount >= 0)` on the
  column; any underflow returns a 500 to the caller and emits
  `nebulacr_gc_underflow_total`. Reconciler corrects on next pass.
- **Reaper crash mid-delete.** The storage delete is best-effort; the
  refcount row deletion is the source of truth. Reconciler detects
  storage objects with no refcount row (`kind='orphan'`) and reaps.
- **Postgres outage.** Pushes block (good — better than corrupting
  state). Pulls are unaffected. Reaper pauses; on recovery, no
  catch-up backlog because zeroed timestamps are durable.
- **Storage backend rate limit.** Token bucket throttles. On 429,
  back off 30 s. Reap rate degrades; correctness preserved.

## g. Migration story

`[gc.online]` section in `nebulacr.toml`, `enabled = false` ships a
no-op; the schema is created but the reaper task is not spawned and
the manifest paths skip the refcount writes (cfg-gated).

Enabling on an existing registry requires a one-time backfill:

```bash
nebulacr gc reconcile --tenant '*' --backfill
```

This runs the reconciler in its `populate-from-empty` mode: every
manifest row is walked, blob descriptors emitted into
`manifest_blob_refs`, refcounts re-summed. Backfill is restartable
(uses a cursor in `gc_drift` table). After backfill the operator
flips `online_reap: true` and restarts the registry; the reaper
starts draining the zero-refcount tail.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Refcount unit      | `crates/nebula-gc/tests/refcount_tx.rs`                | Postgres testcontainer, parallel writers   |
| Reaper grace       | `crates/nebula-gc/tests/reaper_grace.rs`               | Asserts in-grace zero-refcount blob survives |
| Reconciler drift   | `crates/nebula-gc/tests/reconcile_drift.rs`            | Plant orphan + missing rows; assert correction |
| Backfill           | `crates/nebula-gc/tests/backfill.rs`                   | Empty refcount table + manifest fixtures    |
| End-to-end         | `tests/e2e/online_gc_e2e.sh`                           | Push/delete loop + assert reaper drains     |
| Crash recovery     | `crates/nebula-gc/tests/crash_recovery.rs`             | Kill reaper mid-loop; assert no double-delete |
| HA (multi-reaper)  | `crates/nebula-gc/tests/ha_skip_locked.rs`             | Two reapers, one queue, no duplicate work   |

## i. Implementation slice count

4 slices, ~4 weeks:

1. `nebula-gc` crate scaffold + schema + `BlobRefCounter` trait +
   Postgres impl + manifest path wiring (gated by cfg flag, default
   off).
2. Continuous reaper with `FOR UPDATE SKIP LOCKED`, token bucket,
   pause/resume control plane.
3. Reconciler in `--backfill` and `--audit` modes; drift table + alerts.
4. Helm values, CLI, MCP tools, e2e tests, migration runbook for
   existing operators (covers backfill cost + Postgres sizing).
