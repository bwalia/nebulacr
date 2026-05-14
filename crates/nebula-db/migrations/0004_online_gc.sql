-- 009 Online GC — refcount-table-backed garbage collection.
--
-- The reaper (slice 2) drains rows whose refcount has been zero for
-- longer than the configured grace period. The reconciler (slice 3)
-- walks `manifest_blob_refs` to recompute refcounts and detect drift.
--
-- All four tables are tenant-scoped so a single-tenant outage doesn't
-- spill across the registry.

-- Live refcount per (tenant, blob).
CREATE TABLE IF NOT EXISTS blob_refcounts (
    tenant         TEXT NOT NULL,
    blob_digest    TEXT NOT NULL,
    refcount       BIGINT NOT NULL DEFAULT 0 CHECK (refcount >= 0),
    zeroed_at      TIMESTAMPTZ,
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bytes          BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant, blob_digest)
);

-- Hot path query for the reaper: rows with refcount=0 older than grace.
CREATE INDEX IF NOT EXISTS blob_refcounts_zero_idx
    ON blob_refcounts (tenant, zeroed_at)
    WHERE refcount = 0;

-- Manifest -> blob edges. Lets us decrement refcounts when a manifest
-- is deleted without re-parsing its bytes, and lets the reconciler
-- recompute refcounts from authoritative state.
CREATE TABLE IF NOT EXISTS manifest_blob_refs (
    tenant            TEXT NOT NULL,
    manifest_digest   TEXT NOT NULL,
    blob_digest       TEXT NOT NULL,
    PRIMARY KEY (tenant, manifest_digest, blob_digest)
);
CREATE INDEX IF NOT EXISTS manifest_blob_refs_blob_idx
    ON manifest_blob_refs (tenant, blob_digest);

-- Audit ledger of every reap. Slice 2 fills this in.
CREATE TABLE IF NOT EXISTS gc_reaps (
    id            BIGSERIAL PRIMARY KEY,
    tenant        TEXT NOT NULL,
    blob_digest   TEXT NOT NULL,
    bytes_freed   BIGINT NOT NULL,
    reaped_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reconciler    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS gc_reaps_at_idx ON gc_reaps (reaped_at DESC);

-- Reconciler drift findings. Slice 3 fills this in.
CREATE TABLE IF NOT EXISTS gc_drift (
    id            BIGSERIAL PRIMARY KEY,
    tenant        TEXT NOT NULL,
    blob_digest   TEXT NOT NULL,
    kind          TEXT NOT NULL,                   -- 'orphan' | 'missing' | 'underflow'
    expected      BIGINT NOT NULL,
    observed      BIGINT NOT NULL,
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    corrected_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS gc_drift_open_idx
    ON gc_drift (tenant, detected_at DESC)
    WHERE corrected_at IS NULL;
