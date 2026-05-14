-- 013 Ephemeral repositories + TTL tags.
--
-- Slice 1 ships the schema and (in nebula-ephemeral) the TTL header
-- parser. The reaper task wires up in slice 2.
--
-- Note: 003 (tag immutability/quarantine) is also planned to extend
-- the `tags` table; we create a minimal version here so 013 can ship
-- standalone. When 003 lands it ALTER TABLEs in additional columns.

CREATE TABLE IF NOT EXISTS tags (
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    repository      TEXT NOT NULL,
    tag             TEXT NOT NULL,
    digest          TEXT NOT NULL,
    pushed_by       TEXT,
    pushed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_pulled_at  TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    ephemeral       BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant, project, repository, tag)
);
CREATE INDEX IF NOT EXISTS tags_expires_idx
    ON tags (expires_at)
    WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS tags_repo_idx
    ON tags (tenant, project, repository);

CREATE TABLE IF NOT EXISTS ephemeral_repos (
    tenant            TEXT NOT NULL,
    project           TEXT NOT NULL,
    repository        TEXT NOT NULL,
    default_ttl_secs  BIGINT NOT NULL,
    max_ttl_secs      BIGINT NOT NULL,
    expires_at        TIMESTAMPTZ,
    expire_on_empty   BOOLEAN NOT NULL DEFAULT TRUE,
    scm_provider      TEXT,
    scm_pr_url        TEXT,
    scm_state         TEXT NOT NULL DEFAULT 'open',     -- open | closed | merged
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant, project, repository)
);
CREATE INDEX IF NOT EXISTS ephemeral_repos_state_idx
    ON ephemeral_repos (scm_state, expires_at);

CREATE TABLE IF NOT EXISTS ttl_reaps (
    id              BIGSERIAL PRIMARY KEY,
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    repository      TEXT NOT NULL,
    tag             TEXT NOT NULL,
    reaped_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason          TEXT NOT NULL                     -- 'ttl' | 'pr-closed' | 'repo-expired'
);
CREATE INDEX IF NOT EXISTS ttl_reaps_at_idx ON ttl_reaps (reaped_at DESC);
