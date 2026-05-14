-- 011 P2P pull mesh — registry-side membership + stats.
--
-- Slice 1 ships only the schema; the libp2p mesh transport and the
-- DaemonSet binary land in later slices.

CREATE TABLE IF NOT EXISTS peer_meshes (
    id                UUID PRIMARY KEY,
    cluster_name      TEXT NOT NULL UNIQUE,
    bootstrap_url     TEXT NOT NULL,
    last_heartbeat    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    peer_count        INT NOT NULL DEFAULT 0,
    config_yaml       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS peer_nodes (
    id                UUID PRIMARY KEY,
    mesh_id           UUID NOT NULL REFERENCES peer_meshes(id) ON DELETE CASCADE,
    node_name         TEXT NOT NULL,
    libp2p_id         TEXT NOT NULL,
    addr              INET,
    cache_bytes_used  BIGINT NOT NULL DEFAULT 0,
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (mesh_id, node_name)
);
CREATE INDEX IF NOT EXISTS peer_nodes_seen_idx ON peer_nodes (last_seen DESC);

CREATE TABLE IF NOT EXISTS peer_stats_hourly (
    mesh_id          UUID NOT NULL REFERENCES peer_meshes(id) ON DELETE CASCADE,
    bucket_at        TIMESTAMPTZ NOT NULL,
    bytes_origin     BIGINT NOT NULL DEFAULT 0,
    bytes_peer       BIGINT NOT NULL DEFAULT 0,
    bytes_local      BIGINT NOT NULL DEFAULT 0,
    pulls            BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (mesh_id, bucket_at)
);
