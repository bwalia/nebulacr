-- 010 Lazy pulling — eStargz / zstd-chunked / SOCI indexer state.
--
-- The indexer (slice 2-3) walks layers asynchronously after push and
-- writes a TOC artifact registered as a referrer of the manifest.

CREATE TABLE IF NOT EXISTS lazy_index (
    layer_digest    TEXT NOT NULL,
    format          TEXT NOT NULL,                  -- 'estargz' | 'zstd-chunked' | 'soci'
    indexed_digest  TEXT NOT NULL,                  -- new blob (or =layer_digest for SOCI)
    toc_digest      TEXT NOT NULL,
    bytes_original  BIGINT NOT NULL,
    bytes_indexed   BIGINT NOT NULL,
    indexed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (layer_digest, format)
);
CREATE INDEX IF NOT EXISTS lazy_index_format_idx
    ON lazy_index (format, indexed_at DESC);

CREATE TABLE IF NOT EXISTS lazy_jobs (
    id              UUID PRIMARY KEY,
    layer_digest    TEXT NOT NULL,
    format          TEXT NOT NULL,
    status          TEXT NOT NULL,                  -- 'queued' | 'running' | 'done' | 'failed'
    error           TEXT,
    enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    attempts        INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS lazy_jobs_status_idx
    ON lazy_jobs (status, enqueued_at);
CREATE INDEX IF NOT EXISTS lazy_jobs_layer_idx
    ON lazy_jobs (layer_digest, format);

-- OCI 1.1 referrer rows. Shared across 010 (TOC), 015 (attestations),
-- and future producers (014 cyclonedx export, etc.). The pair
-- (subject_digest, artifact_digest) is unique.
CREATE TABLE IF NOT EXISTS referrers (
    subject_digest  TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    artifact_type   TEXT NOT NULL,
    media_type      TEXT NOT NULL,
    size            BIGINT NOT NULL,
    PRIMARY KEY (subject_digest, artifact_digest)
);
CREATE INDEX IF NOT EXISTS referrers_subject_idx ON referrers (subject_digest);
CREATE INDEX IF NOT EXISTS referrers_type_idx ON referrers (artifact_type);
