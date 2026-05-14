-- 015 SLSA provenance / in-toto attestations.

CREATE TABLE IF NOT EXISTS attestations (
    id              UUID PRIMARY KEY,
    subject_digest  TEXT NOT NULL,
    envelope_digest TEXT NOT NULL,
    predicate_type  TEXT NOT NULL,
    builder_id      TEXT,
    builder_kind    TEXT,
    slsa_level      INT,                           -- 0..3
    materials       JSONB,
    signed_by       TEXT,
    verified        BOOLEAN NOT NULL,
    verified_at     TIMESTAMPTZ,
    raw             JSONB NOT NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS attestations_subject_idx   ON attestations (subject_digest);
CREATE INDEX IF NOT EXISTS attestations_predicate_idx ON attestations (predicate_type);
CREATE INDEX IF NOT EXISTS attestations_builder_idx   ON attestations (builder_id);

CREATE TABLE IF NOT EXISTS attestation_policies (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    name            TEXT NOT NULL,
    spec            JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, name)
);

CREATE TABLE IF NOT EXISTS trusted_builders (
    issuer          TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    name            TEXT NOT NULL,
    notes           TEXT
);
