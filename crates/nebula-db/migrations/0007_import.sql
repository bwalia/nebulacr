-- 012 Migration importer — Nexus / Harbor / ACR / Distribution copy state.

CREATE TABLE IF NOT EXISTS import_jobs (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    spec            JSONB NOT NULL,
    phase           TEXT NOT NULL,                  -- queued | running | succeeded | failed | aborted
    repos_total     INT NOT NULL DEFAULT 0,
    repos_copied    INT NOT NULL DEFAULT 0,
    tags_total      INT NOT NULL DEFAULT 0,
    tags_copied     INT NOT NULL DEFAULT 0,
    bytes_copied    BIGINT NOT NULL DEFAULT 0,
    resume_cursor   TEXT,
    started_at      TIMESTAMPTZ,
    last_activity   TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS import_jobs_phase_idx
    ON import_jobs (phase, started_at DESC);

-- Per-tag idempotency.
CREATE TABLE IF NOT EXISTS import_tag_state (
    job_id          UUID NOT NULL REFERENCES import_jobs(id) ON DELETE CASCADE,
    src_repo        TEXT NOT NULL,
    src_tag         TEXT NOT NULL,
    src_digest      TEXT NOT NULL,
    dst_digest      TEXT,
    bytes           BIGINT,
    state           TEXT NOT NULL,                  -- pending | copying | done | failed
    error           TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, src_repo, src_tag)
);
CREATE INDEX IF NOT EXISTS import_tag_state_pending_idx
    ON import_tag_state (job_id, state)
    WHERE state IN ('pending','copying');

-- Per-blob dedup (within a job).
CREATE TABLE IF NOT EXISTS import_blob_seen (
    job_id          UUID NOT NULL REFERENCES import_jobs(id) ON DELETE CASCADE,
    digest          TEXT NOT NULL,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, digest)
);
