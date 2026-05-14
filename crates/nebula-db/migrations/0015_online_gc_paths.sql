-- 009 Online GC slice 2 — blob storage path index.
--
-- The slice-1 refcount table is keyed on (tenant, blob_digest) — the
-- granularity at which content can be deduped logically. Storage,
-- however, lives at <tenant>/<project>/<repo>/blobs/sha256/<hex> —
-- one copy per repository. The reaper needs to know every path so
-- it can delete them all when a digest's refcount drops to zero.
--
-- This table is populated by `add_refs` whenever a manifest registers
-- new blob edges, and rows are removed by the reaper after the
-- corresponding storage object is deleted.

CREATE TABLE IF NOT EXISTS blob_paths (
    tenant       TEXT NOT NULL,
    project      TEXT NOT NULL,
    repository   TEXT NOT NULL,
    blob_digest  TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant, project, repository, blob_digest)
);

-- Reverse-index for the reaper's "where does this digest live?" query.
CREATE INDEX IF NOT EXISTS blob_paths_digest_idx
    ON blob_paths (tenant, blob_digest);
