-- 018 Auto-rebuild on base CVE patch.

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS parent_image_ref TEXT,
    ADD COLUMN IF NOT EXISTS parent_digest TEXT;

CREATE TABLE IF NOT EXISTS image_lineage (
    child_digest    TEXT NOT NULL,
    parent_digest   TEXT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confidence      TEXT NOT NULL,                  -- 'label' | 'history' | 'inferred'
    PRIMARY KEY (child_digest, parent_digest)
);
CREATE INDEX IF NOT EXISTS image_lineage_parent_idx
    ON image_lineage (parent_digest);

CREATE TABLE IF NOT EXISTS rebuild_subscriptions (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    name            TEXT NOT NULL,
    spec            JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, name)
);

CREATE TABLE IF NOT EXISTS rebuild_events (
    id                UUID PRIMARY KEY,
    subscription_id   UUID NOT NULL REFERENCES rebuild_subscriptions(id) ON DELETE CASCADE,
    upstream_ref      TEXT NOT NULL,
    downstream_ref    TEXT NOT NULL,
    fixed_cves        TEXT[] NOT NULL,
    severity_max      TEXT NOT NULL,
    emitter_status    TEXT NOT NULL,
    emitter_response  TEXT,
    fired_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS rebuild_events_sub_at_idx
    ON rebuild_events (subscription_id, fired_at DESC);

CREATE TABLE IF NOT EXISTS rebuild_rate (
    subscription_id UUID NOT NULL REFERENCES rebuild_subscriptions(id) ON DELETE CASCADE,
    downstream_ref  TEXT NOT NULL,
    bucket_day      DATE NOT NULL,
    fired           INT NOT NULL DEFAULT 1,
    PRIMARY KEY (subscription_id, downstream_ref, bucket_day)
);
