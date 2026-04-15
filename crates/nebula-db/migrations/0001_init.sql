-- NebulaCR scanner schema, initial revision.

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY,
    digest TEXT NOT NULL,
    tenant TEXT NOT NULL,
    project TEXT NOT NULL,
    repository TEXT NOT NULL,
    reference TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    medium_count INT NOT NULL DEFAULT 0,
    low_count INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS scans_digest_idx ON scans (digest);
CREATE INDEX IF NOT EXISTS scans_repo_idx ON scans (tenant, project, repository);
CREATE INDEX IF NOT EXISTS scans_status_idx ON scans (status) WHERE status IN ('queued', 'in_progress');

-- Vulnerabilities cache (populated by own-DB ingestion in slice 2).
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,                -- CVE-YYYY-NNNN or GHSA-xxxx
    source TEXT NOT NULL,               -- nvd | osv | ghsa | distro
    summary TEXT,
    description TEXT,
    severity TEXT,
    cvss_score DOUBLE PRECISION,
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw JSONB
);
CREATE INDEX IF NOT EXISTS vulnerabilities_severity_idx ON vulnerabilities (severity);

-- Affected ranges (PURL ecosystem + version range), one row per (vuln, package).
CREATE TABLE IF NOT EXISTS affected_ranges (
    id BIGSERIAL PRIMARY KEY,
    vuln_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,            -- npm | cargo | pypi | deb | rpm | apk | go | maven
    package TEXT NOT NULL,
    introduced TEXT,
    fixed TEXT,
    last_affected TEXT,
    purl TEXT
);
CREATE INDEX IF NOT EXISTS affected_ranges_lookup_idx ON affected_ranges (ecosystem, package);

-- Suppressions.
CREATE TABLE IF NOT EXISTS suppressions (
    id UUID PRIMARY KEY,
    cve_id TEXT NOT NULL,
    scope_tenant TEXT,
    scope_project TEXT,
    scope_repository TEXT,
    scope_package TEXT,
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS suppressions_cve_idx ON suppressions (cve_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS suppressions_scope_idx ON suppressions (scope_tenant, scope_project, scope_repository) WHERE revoked_at IS NULL;

-- Immutable audit log.
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log (actor, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_target_idx ON audit_log (target_kind, target_id);

-- Per-repository scan configuration.
CREATE TABLE IF NOT EXISTS image_settings (
    tenant TEXT NOT NULL,
    project TEXT NOT NULL,
    repository TEXT NOT NULL,
    scan_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    policy_yaml TEXT,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant, project, repository)
);

-- Scanner API keys (CI/CD).
CREATE TABLE IF NOT EXISTS scanner_api_keys (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    tenant TEXT,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS scanner_api_keys_active_idx ON scanner_api_keys (key_hash) WHERE revoked_at IS NULL;
