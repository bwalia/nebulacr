# 015 — SLSA Provenance & in-toto Attestation Storage

> **Summary.** Accept, store, and verify SLSA-flavour in-toto
> attestations alongside cosign signatures (001) and TOC artifacts
> (010), all under the same OCI 1.1 referrers convention. A
> per-project policy can require a SLSA Build Level (L1/L2/L3) and
> a known builder identity (e.g. `https://github.com/actions`); the
> 002 admission gate consults this just like signature verification.
> CLI shortcuts (`nebulacr attest verify`) let teams trust provenance
> without standing up a separate Rekor / TUF server.

## a. Problem statement

The supply-chain ecosystem agreed on in-toto + SLSA for proving
*how* an image was built, but every registry treats attestations as
opaque artifacts at best. Cosign uploads them as adjacent OCI
artifacts; nothing in any registry checks the SLSA level, the
builder identity, or the materials list at pull time. Compliance
teams who want "no L0 builds in prod" have to write their own
Kyverno / OPA policies after the pull. NebulaCR can shift this left:
the registry refuses to *serve* a build that doesn't meet the
configured SLSA bar.

## b. Proposed approach

New crate `nebula-attest`. Architecture mirrors 001's `Verifier`:

```rust
// crates/nebula-attest/src/lib.rs
#[async_trait]
pub trait AttestationStore: Send + Sync {
    async fn put(&self, subject: Digest, env: DsseEnvelope)
        -> Result<Descriptor, AttestError>;
    async fn list(&self, subject: Digest)
        -> Result<Vec<Attestation>, AttestError>;
}

#[async_trait]
pub trait AttestationVerifier: Send + Sync {
    async fn verify(&self, env: &DsseEnvelope, policy: &SlsaPolicy)
        -> Result<SlsaVerdict, AttestError>;
}

pub struct SlsaPolicy {
    pub min_level: SlsaLevel,           // L1..L3
    pub allowed_builders: Vec<BuilderId>,
    pub required_materials: Vec<MaterialPattern>,    // e.g. github.com/acme/api*
    pub max_age: Duration,
}

pub enum SlsaVerdict {
    Pass { level: SlsaLevel, builder: BuilderId },
    Fail { reason: String, predicate: Option<String> },
}
```

Storage: every uploaded attestation is an OCI artifact (mediaType
`application/vnd.dev.sigstore.bundle.v0.3+json` or
`application/vnd.in-toto+json`) registered as a referrer of the
subject manifest. The same `referrers` table from 010 holds the
edge; the DSSE envelope itself is just another blob. No special
storage path.

Acceptance flow (push):

1. Client `POST /v2/<name>/blobs/uploads/...` for the envelope
   bytes (existing blob upload path).
2. Client `PUT /v2/<name>/manifests/<sha256:envelope>` with mediaType
   set to one of the attestation media types.
3. Registry detects the media type, extracts `subject.digest` from
   the in-toto statement, and writes a `referrers` row + an
   `attestations` row containing the parsed predicate type
   (`https://slsa.dev/provenance/v1`, `cyclonedx`, `vuln`, etc.).
4. If 001 signing is enabled, the DSSE signature is verified
   immediately; failures are stored as `verified: false` and surfaced
   in the dashboard.

Verification flow (pull):

1. 002 admission gate reads `policy.attestation` block.
2. Calls `AttestationVerifier::verify(envelope, slsa_policy)`.
3. Verifier:
   - Decodes DSSE, validates signatures via `nebula-signing`.
   - Parses predicate as SLSA Provenance v0.2 / v1.0.
   - Walks `runDetails.builder.id` against `allowed_builders`.
   - Walks `runDetails.metadata` for SLSA-Level annotations + cross-
     references with `nebula-signing`'s issuer to assign a level
     (signed by Fulcio root + builder id matches → L3 candidate).
4. Verdict cached in Redis (same admission cache as 002).

Builder-identity mapping is config:

```toml
[attestation.builders]
"https://token.actions.githubusercontent.com" = "github-actions"
"https://accounts.google.com"                  = "cloud-build"
```

CLI: `nebulacr attest push <ref> --predicate slsa-prov.json
--key-id k1`, `nebulacr attest list <ref>`, `nebulacr attest verify
<ref> --policy prod-slsa-l3`. MCP: `list_attestations`,
`verify_attestation`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: AdmissionPolicy
metadata:
  name: prod-slsa-l3
spec:
  tenantRef: acme
  scope: { projects: ["prod"] }
  attestation:
    required: true
    minLevel: L3
    allowedBuilders:
      - github-actions
      - tekton-chains
    requiredPredicates:
      - https://slsa.dev/provenance/v1
    requiredMaterials:
      - pattern: github.com/acme/*
        verifyExists: true
    maxAgeDays: 90
  cve:
    block: { critical: ">0" }
```

Project CRD gets a default policy reference:

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Project
spec:
  defaultAttestationPolicy: prod-slsa-l3
```

## d. New HTTP routes

| Method | Path                                                       | Auth scope         | Notes                                            |
| ------ | ---------------------------------------------------------- | ------------------ | ------------------------------------------------ |
| POST   | `/v2/<name>/attestations`                                  | `repo:push`        | Direct attestation upload (bypasses manifest PUT) |
| GET    | `/v2/<name>/attestations/<digest>`                         | `repo:pull`        | List attestations for a subject                  |
| POST   | `/v2/<name>/attestations/{digest}/verify`                  | `repo:pull`        | Body `{policy}` → SlsaVerdict                    |
| GET    | `/v2/_attestation/policies`                                | `tenant:read`      | List configured SLSA policies                    |
| POST   | `/v2/_attestation/policies`                                | `tenant:admin`     | Create/update                                     |
| GET    | `/v2/<name>/referrers/<digest>?artifactType=in-toto`       | `repo:pull`        | OCI 1.1 referrers filtered to attestations       |

The cosign / sigstore CLI uses
`POST /v2/<name>/manifests/<digest>` with the bundle media type and
expects standard OCI semantics — that path stays the canonical
upload route. The `_attestation` endpoints are NebulaCR-specific
conveniences.

## e. Storage / Postgres schema

```sql
-- 0015_attestations.sql
CREATE TABLE attestations (
    id              UUID PRIMARY KEY,
    subject_digest  TEXT NOT NULL,
    envelope_digest TEXT NOT NULL,                 -- the DSSE blob
    predicate_type  TEXT NOT NULL,                 -- https://slsa.dev/provenance/v1
    builder_id      TEXT,
    builder_kind    TEXT,                          -- 'github-actions' | 'tekton-chains' | ...
    slsa_level      INT,                           -- 0..3
    materials       JSONB,                         -- normalised list
    signed_by       TEXT,                          -- cosign issuer + subject
    verified        BOOLEAN NOT NULL,
    verified_at     TIMESTAMPTZ,
    raw             JSONB NOT NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX attestations_subject_idx     ON attestations (subject_digest);
CREATE INDEX attestations_predicate_idx   ON attestations (predicate_type);
CREATE INDEX attestations_builder_idx     ON attestations (builder_id);

CREATE TABLE attestation_policies (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    name            TEXT NOT NULL,
    spec            JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, name)
);

-- Trusted-builder identity allowlist (separate table for fast lookup)
CREATE TABLE trusted_builders (
    issuer          TEXT PRIMARY KEY,              -- OIDC issuer URL
    kind            TEXT NOT NULL,
    name            TEXT NOT NULL,
    notes           TEXT
);
```

The attestation envelope itself is stored as a blob in the
content-addressed store; only the parsed metadata lives in
Postgres.

## f. Failure modes

- **DSSE signature invalid.** `verified=false`; admission gate
  treats as no-attestation-present unless `policy.required=true`,
  in which case pull blocks.
- **Predicate is unknown type** (e.g. SBOM rather than provenance).
  Stored as-is; level computation skipped. Admission policy
  ignores unless predicate is `requiredPredicates`.
- **Cosign issuer not in `trusted_builders`.** `slsa_level = 0`;
  attestation accepted but unable to satisfy ≥L1 policies.
- **Attestation post-dates `maxAgeDays`.** Rejected at pull;
  `WWW-NebulaCR-Reason: attestation-stale`.
- **Multiple attestations for same predicate.** Admission gate
  uses the most recent verified one. Older ones are kept for
  audit but not consulted.
- **001 signing disabled, but attestation policy requires
  signature verification.** Controller webhook rejects the policy
  CRD with a clear error pointing at `[signing] enabled`.

## g. Migration story

`[attestation] enabled = false`. Schema ships; the parse path on
manifest PUT skips attestation media types. Once enabled, existing
deployments accept uploads but admission policies only enforce
when configured.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| DSSE parse         | `crates/nebula-attest/tests/dsse_parse.rs`             | Cosign-generated bundle fixtures           |
| SLSA L1/L2/L3      | `crates/nebula-attest/tests/slsa_levels.rs`            | Fixture per level; expected level computed  |
| Builder allowlist  | `crates/nebula-attest/tests/builders.rs`               | Unknown issuer → L0                         |
| Verify integration | `crates/nebula-registry/tests/attest_admit.rs`         | E2E with 002 admission gate                 |
| Stale rejection    | `crates/nebula-attest/tests/maxage.rs`                 | Old attestation blocked                     |
| Cosign compat      | `tests/e2e/cosign_attest_e2e.sh`                       | Real `cosign attest` against the registry   |

External e2e dep: `cosign` binary in CI. Same image used by 001
tests.

## i. Implementation slice count

3 slices, ~3 weeks:

1. `nebula-attest` crate scaffold + `attestations` schema + manifest
   PUT detection of in-toto media types + envelope parse + storage.
2. SLSA level computation + builder allowlist + `AttestationPolicy`
   CRD + verifier integration with `nebula-signing`.
3. 002 admission gate wiring + CLI/MCP + cosign e2e + docs (recipe
   per CI builder: GitHub Actions, Tekton Chains, Buildkit + Rekor).
