-- scan_jobs: durable queue of pending scans. Registry pushes enqueue a row;
-- scanner workers claim-and-delete (atomic via SKIP LOCKED) to run them.
-- At-most-once semantics — a worker crash mid-scan loses the job; re-push
-- the image to re-trigger. The separate `scans` table keeps scan results.
CREATE TABLE IF NOT EXISTS scan_jobs (
    id          UUID        PRIMARY KEY,
    digest      TEXT        NOT NULL,
    tenant      TEXT        NOT NULL,
    project     TEXT        NOT NULL,
    repository  TEXT        NOT NULL,
    reference   TEXT        NOT NULL,
    enqueued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS scan_jobs_enqueued_at_idx
    ON scan_jobs (enqueued_at);
