-- 014 Extended scanning — unified findings table for CVE / license /
-- secret / malware. Generalises the existing CVE pipeline.

CREATE TABLE IF NOT EXISTS findings (
    id              UUID PRIMARY KEY,
    scan_id         UUID NOT NULL,
    digest          TEXT NOT NULL,
    detector        TEXT NOT NULL,            -- 'cve' | 'license' | 'secret' | 'malware'
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    finding_id      TEXT NOT NULL,            -- CVE / SPDX / rule id / signature
    package_purl    TEXT,
    path            TEXT,
    line            INT,
    fix             JSONB,
    raw             JSONB NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS findings_digest_idx       ON findings (digest);
CREATE INDEX IF NOT EXISTS findings_detector_sev_idx ON findings (detector, severity);
CREATE INDEX IF NOT EXISTS findings_finding_id_idx   ON findings (finding_id);

-- Generalise existing suppressions to all detectors.
ALTER TABLE suppressions
    ADD COLUMN IF NOT EXISTS detector TEXT NOT NULL DEFAULT 'cve';
CREATE INDEX IF NOT EXISTS suppressions_detector_idx
    ON suppressions (detector, cve_id);

-- License DB cache (refreshed from upstream SPDX list weekly)
CREATE TABLE IF NOT EXISTS license_definitions (
    spdx_id         TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    class           TEXT NOT NULL,            -- permissive | weak-copyleft | ...
    osi_approved    BOOLEAN NOT NULL,
    fsf_libre       BOOLEAN NOT NULL,
    text_hash       BYTEA,
    refreshed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
