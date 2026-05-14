-- 017 Cost & pull-telemetry — usage events + rollups + cost models.
--
-- Slice 1 ships the staging table and the durable hourly/daily rollup
-- tables. The drainer task that feeds them lives in nebula-cost.

CREATE UNLOGGED TABLE IF NOT EXISTS usage_events_staging (
    at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant     TEXT NOT NULL,
    project    TEXT NOT NULL,
    repository TEXT NOT NULL,
    op         TEXT NOT NULL,                       -- pull | push | manifest_get | manifest_put
    bytes      BIGINT NOT NULL,
    src        TEXT NOT NULL,                       -- origin | cache | peer | pull-through
    status     INT NOT NULL,
    ip         INET,
    sub        TEXT
);
CREATE INDEX IF NOT EXISTS usage_events_staging_at_idx
    ON usage_events_staging (at);

-- Durable copy. Partitioning is operator's choice for now; default is
-- a single non-partitioned table — operators with high traffic use
-- pg_partman or attach partitions manually.
CREATE TABLE IF NOT EXISTS usage_events (
    LIKE usage_events_staging INCLUDING ALL
);
CREATE INDEX IF NOT EXISTS usage_events_at_tenant_idx
    ON usage_events (at DESC, tenant);

CREATE TABLE IF NOT EXISTS usage_hourly (
    bucket_at      TIMESTAMPTZ NOT NULL,
    tenant         TEXT NOT NULL,
    project        TEXT NOT NULL,
    repository     TEXT NOT NULL,
    op             TEXT NOT NULL,
    src            TEXT NOT NULL,
    bytes          BIGINT NOT NULL,
    requests       BIGINT NOT NULL,
    PRIMARY KEY (bucket_at, tenant, project, repository, op, src)
);
CREATE INDEX IF NOT EXISTS usage_hourly_tenant_idx
    ON usage_hourly (tenant, bucket_at DESC);

CREATE TABLE IF NOT EXISTS usage_daily (
    LIKE usage_hourly INCLUDING ALL
);

CREATE TABLE IF NOT EXISTS usage_baselines (
    tenant         TEXT NOT NULL,
    op             TEXT NOT NULL,
    mean_bytes     DOUBLE PRECISION NOT NULL,
    stddev_bytes   DOUBLE PRECISION NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant, op)
);

CREATE TABLE IF NOT EXISTS cost_models (
    name           TEXT PRIMARY KEY,
    spec           JSONB NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
