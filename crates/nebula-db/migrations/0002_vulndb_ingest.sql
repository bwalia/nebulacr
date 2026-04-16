-- Vuln-DB ingestion support (slice 2a).
--
-- `ingest_cursor` stores per-source checkpoints so that re-running an
-- ingester can short-circuit when the upstream feed is unchanged (HTTP
-- ETag for zip-based feeds like OSV, last-modified timestamp for API
-- feeds like NVD 2.0). `last_run_*` columns give operators visibility
-- into ingester health without a separate metrics pipeline.
CREATE TABLE IF NOT EXISTS ingest_cursor (
    source TEXT PRIMARY KEY,             -- osv | nvd | ghsa
    etag TEXT,
    last_modified TIMESTAMPTZ,
    last_run_at TIMESTAMPTZ,
    last_run_advisories INT,
    last_run_error TEXT
);

-- Speeds up the DELETE-then-INSERT pattern the ingester uses to refresh
-- an advisory's ranges atomically. Without this, re-ingest of a 200k-row
-- advisory set turns into a sequential scan per vuln.
CREATE INDEX IF NOT EXISTS affected_ranges_vuln_idx
    ON affected_ranges (vuln_id);

-- Supports delta-ingest queries ("what changed since T?") and operator
-- debugging ("what did we last import?").
CREATE INDEX IF NOT EXISTS vulnerabilities_modified_idx
    ON vulnerabilities (modified_at DESC);
