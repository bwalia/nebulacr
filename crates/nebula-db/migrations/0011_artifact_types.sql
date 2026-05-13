-- 016 Typed-artifact registries — Helm / WASM / model / Terraform.

CREATE TABLE IF NOT EXISTS artifact_meta (
    digest          TEXT PRIMARY KEY,
    type_id         TEXT NOT NULL,                   -- 'helm' | 'wasm' | 'model' | 'tfmodule'
    metadata        JSONB NOT NULL,
    media_type      TEXT NOT NULL,
    bytes           BIGINT NOT NULL,
    validated       BOOLEAN NOT NULL,
    validation_msg  TEXT,
    parsed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS artifact_meta_type_idx ON artifact_meta (type_id);
CREATE INDEX IF NOT EXISTS artifact_meta_meta_idx ON artifact_meta USING GIN (metadata jsonb_path_ops);

CREATE TABLE IF NOT EXISTS artifact_index (
    type_id         TEXT NOT NULL,
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    name            TEXT NOT NULL,
    versions        JSONB NOT NULL,
    PRIMARY KEY (type_id, tenant, project, name)
);
