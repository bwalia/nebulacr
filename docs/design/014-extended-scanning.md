# 014 — Extended Scanning: License, Secret, Malware

> **Summary.** Add three new scanner modules alongside the existing
> CVE scanner: a license scanner that produces an SPDX licence map of
> every artifact and gates pulls on policy; a secret scanner that
> detects leaked credentials in image filesystems; and a malware
> scanner backed by `clamav-rs` (or a swappable engine via the
> existing scanner-trait pattern). All three reuse the layer-walking
> pipeline already in `nebula-scanner`, store findings in Postgres,
> and feed verdicts into the 002 admission gate.

## a. Problem statement

CVE scanning catches known vulnerable packages but is silent on the
other three classes of supply-chain risk: GPL-licensed code in
proprietary images, AWS keys baked into a layer, and malware
embedded in a base image. ACR's "Defender for Cloud" partially
addresses malware (proprietary, paid). Sonatype IQ checks licences
but is a separate product. None of the OSS registries ship an
integrated story. The cost to add each new scanner type is small
because the layer extraction, queue, store, and policy plumbing
already exist.

## b. Proposed approach

Generalise the scanner crate from "CVE only" to "any finding type"
behind a trait `Detector`, mirroring the existing `VulnDb` trait
shape:

```rust
// crates/nebula-scanner/src/detector/mod.rs
#[async_trait]
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;                  // "cve" | "license" | "secret" | "malware"
    fn finding_kind(&self) -> FindingKind;

    /// Walks the layer's tarball; returns findings.
    async fn scan(&self, layer: LayerHandle<'_>)
        -> Result<Vec<Finding>, DetectorError>;
}

pub struct CveDetector { /* wraps existing SBOM + matcher pipeline */ }
pub struct LicenseDetector { db: Arc<dyn LicenseDb> }
pub struct SecretDetector { rules: Arc<RuleSet> }
pub struct MalwareDetector { engine: Arc<dyn MalwareEngine> }
```

Each detector emits `Finding`s with a common envelope so the dashboard
and API are uniform:

```rust
pub struct Finding {
    pub kind: FindingKind,                          // Cve | License | Secret | Malware
    pub severity: Severity,                         // critical | high | medium | low | info
    pub id: String,                                 // CVE id | SPDX id | rule id | signature
    pub title: String,
    pub package: Option<PackageRef>,                // for cve / license
    pub path: Option<String>,                       // for secret / malware
    pub line: Option<u32>,
    pub fix: Option<FixSuggestion>,
}
```

Detector specifics:

### License (SPDX)

`LicenseDb` is a trait — first impl wraps the SPDX licence list
JSON. Detector extracts package metadata produced by the existing
SBOM walker, looks up SPDX id, classifies as
`permissive | weak-copyleft | strong-copyleft | proprietary | unknown`.
Loose-text `LICENSE` files are matched against ScanCode-style rules
embedded in the binary (no external service). Output is also a
CycloneDX licence map exportable as SPDX JSON.

### Secret

Embedded ruleset based on the `gitleaks` ruleset (regex + entropy
gate). Walks every text-mode file in the tarball with size cap of
2 MiB. False-positive control: per-rule `allowed_paths` regex,
per-tenant suppressions reusing the existing
`crates/nebula-scanner/src/suppress.rs` table. Critical severity
for high-confidence keys (AWS, GCP, Stripe, GitHub PAT); medium for
generic high-entropy strings.

### Malware

`MalwareEngine` trait; first impl uses `clamav-rs`. ClamAV signatures
auto-update via the same `ingest_cursor` table the vulndb already
uses (one row per engine). Engine binary is heavy (~150 MB)
— gated behind a feature flag (`features = ["malware-clamav"]`); the
default registry image does NOT include it. Operators wanting
malware scanning use the `nebulacr-scanner-full` image, which is a
separate Dockerfile target. Future engines (YARA-only, Windows
Defender ATP API, etc.) plug in behind the same trait.

Pipeline: each detector runs on every successful push, in parallel.
The scanner queue work item gains a `detectors: Vec<DetectorId>`
field. Findings land in a single `findings` table; the existing
`PolicyEvaluation` becomes a multi-kind evaluator with per-kind
thresholds.

CLI: `nebulacr scan run <ref> --kind license,secret`,
`nebulacr findings list <ref>`, `nebulacr findings suppress <id>`.
MCP: `list_findings`, `suppress_finding` (already exists for CVE;
extended to all kinds).

## c. New/changed CRDs

The existing scanner config + `AdmissionPolicy` (002) gain per-kind
thresholds:

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: AdmissionPolicy
metadata:
  name: prod-block-criticals
spec:
  tenantRef: acme
  scope:
    projects: ["prod"]
  cve:
    block: { critical: ">0", high: ">5" }
  license:
    block:
      classes: [proprietary, strong-copyleft]    # GPL etc.
    allowList: [Apache-2.0, MIT, BSD-3-Clause, ISC]
  secret:
    block:
      severity: ">=high"                          # any high-confidence key
  malware:
    block:
      anyDetection: true
  onUnknown: scan
  onTimeout: block
```

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Project
spec:
  scanning:
    detectors: [cve, license, secret]            # malware off by default
    sbomFormat: cyclonedx                        # cyclonedx | spdx | both
```

## d. New HTTP routes

| Method | Path                                                   | Auth scope         | Notes                                            |
| ------ | ------------------------------------------------------ | ------------------ | ------------------------------------------------ |
| GET    | `/v2/scan/{id}/findings?kind=license,secret`           | `repo:read`        | Filter by kind                                    |
| GET    | `/v2/scan/{id}/sbom?format=spdx`                       | `repo:read`        | SPDX export (CycloneDX already exists)            |
| GET    | `/v2/scan/{id}/license-report`                         | `repo:read`        | Rendered licence-class summary                     |
| POST   | `/v2/findings/{id}/suppress`                           | `tenant:write`     | Existing `cve/suppress` generalised to all kinds  |
| GET    | `/v2/findings/search?kind=secret&severity=high`        | `tenant:read`      | Cross-image search across all detectors           |
| POST   | `/admin/malware/signatures/refresh`                    | `tenant:admin`     | Manual ClamAV signature refresh                   |

## e. Storage / Postgres schema

```sql
-- 0014_extended_scanning.sql
CREATE TABLE findings (
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
CREATE INDEX findings_digest_idx       ON findings (digest);
CREATE INDEX findings_detector_sev_idx ON findings (detector, severity);
CREATE INDEX findings_finding_id_idx   ON findings (finding_id);

-- Generalise existing suppressions to all detectors. Existing
-- `suppressions` table from CVE scanner is migrated:
ALTER TABLE suppressions
    ADD COLUMN detector TEXT NOT NULL DEFAULT 'cve';
CREATE INDEX suppressions_detector_idx ON suppressions (detector, finding_id);

-- License DB cache (refreshed from upstream SPDX list)
CREATE TABLE license_definitions (
    spdx_id         TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    class           TEXT NOT NULL,            -- permissive | weak-copyleft | ...
    osi_approved    BOOLEAN NOT NULL,
    fsf_libre       BOOLEAN NOT NULL,
    text_hash       BYTEA NOT NULL,
    refreshed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Malware engine signature cursor (reuses ingest_cursor pattern)
INSERT INTO ingest_cursor (source, last_run_at, etag)
VALUES ('clamav', '1970-01-01', NULL)
ON CONFLICT DO NOTHING;
```

The existing `vulnerabilities` and `affected_ranges` tables remain
the CVE-specific store; `findings` is the unified result-set view.
A scan row joins to many findings of mixed kinds.

## f. Failure modes

- **License DB stale.** Upstream SPDX list is fetched weekly; if
  ingest fails the existing list is used (warning emitted). Never
  blocks pushes.
- **Secret false positive on test fixtures.** `allowed_paths` regex
  per rule covers common cases (`testdata/`, `**/test-fixtures/**`).
  Per-tenant suppressions cover the rest. We do NOT block pushes on
  secret findings by default; admission policy must opt in.
- **Malware engine OOM on a 4 GiB layer.** Detector caps single-file
  size (default 100 MiB); larger files are skipped + logged
  (`malware_skipped_total`). Operators tune for their workloads.
- **ClamAV signature update down.** Stale signatures keep working;
  metric `clamav_signatures_age_seconds` exposed. Admins set an
  alert threshold.
- **Detector panics.** Each detector runs in its own task; a panic
  in one does not block the scan completing for the others. The
  scan record records a `partial: true` flag with the failed
  detector list.

## g. Migration story

`[scanning.detectors]` config defaults to `["cve"]` (current
behaviour). Operators add `"license"` / `"secret"` per project. The
`malware` detector requires the `nebulacr-scanner-full` image and
is opt-in even when configured.

`AdmissionPolicy` CRDs without the new blocks behave as today (CVE
only). Adding `license:` etc. to a policy enables enforcement on
the next pull-time evaluation.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| License classifier | `crates/nebula-scanner/tests/license_classify.rs`      | Golden SPDX → class map                     |
| License text match | `crates/nebula-scanner/tests/license_text.rs`          | LICENSE files → SPDX id                     |
| Secret rules       | `crates/nebula-scanner/tests/secret_rules.rs`          | gitleaks fixture corpus                     |
| Secret allowlist   | `crates/nebula-scanner/tests/secret_allowlist.rs`      | testdata/ exclusion                         |
| Malware EICAR      | `crates/nebula-scanner/tests/malware_eicar.rs`         | Standard EICAR test string                  |
| Findings query     | `crates/nebula-scanner/tests/findings_search.rs`       | Cross-detector filter                       |
| End-to-end         | `tests/e2e/extended_scan_e2e.sh`                       | Push image with all 3 issues; verify counts |

EICAR is a standard malware test signature — never a real binary.

## i. Implementation slice count

4 slices, ~4 weeks:

1. `Detector` trait + `findings` table migration + generalise the
   existing CVE pipeline to write through `Detector::scan` (no new
   detectors yet — refactor only).
2. `LicenseDetector` + SPDX list ingest + license-report endpoint.
3. `SecretDetector` + gitleaks rule corpus + per-rule allowlist.
4. `MalwareDetector` (feature-flagged) + ClamAV engine + signature
   refresh job + admission policy wiring + docs.
