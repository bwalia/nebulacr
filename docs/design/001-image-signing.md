# 001 — Cosign/Notation Image Signing + Verification Policies

> **Summary.** Add pure-Rust image signing via `sigstore-rs` behind a
> `Signer`/`Verifier` trait pair. Signatures are stored as OCI artifacts
> alongside the signed manifest using the cosign convention
> (`sha256-<hex>.sig`). Verification policy is a new
> `ImageVerificationPolicy` CRD. v1 ships keyed signing; keyless (Fulcio +
> Rekor) is wired through the same trait so it can land in v1.1 without
> schema changes.

## a. Problem statement

ACR ships `az acr import --signed`, native cosign verification on pull, and
keyless OIDC signing via Notation. Nexus has Sonatype Lifecycle policy
hooks for signed-image enforcement. NebulaCR today emits a webhook on push
(`crates/nebula-registry/src/main.rs:964`) and stops. There is no
signature primitive, no verification on pull, and no policy CRD wiring.
Without this, users cannot meet supply-chain compliance requirements
(SLSA L3, FedRAMP, EU CRA).

## b. Proposed approach

New crate `nebula-signing` exposing two traits:

```rust
// crates/nebula-signing/src/lib.rs
#[async_trait]
pub trait Signer: Send + Sync {
    /// Sign the descriptor of a manifest by digest. Returns a cosign
    /// `.sig` artifact body and its OCI media type.
    async fn sign(
        &self,
        subject_digest: &str,
        identity: &SigningIdentity,
    ) -> Result<SignatureArtifact, SignError>;
}

#[async_trait]
pub trait Verifier: Send + Sync {
    /// Verify all signatures attached to `subject_digest` against `policy`.
    async fn verify(
        &self,
        subject_digest: &str,
        signatures: &[SignatureArtifact],
        policy: &VerificationPolicy,
    ) -> Result<VerificationOutcome, VerifyError>;
}

pub enum SigningIdentity {
    Keyed { key_ref: String },                  // PEM in Vault / KMS
    Keyless { fulcio: FulcioConfig, oidc: OidcToken }, // v1.1
}

pub struct VerificationOutcome {
    pub trusted: bool,
    pub matched_signers: Vec<String>,
    pub policy_id: Uuid,
}
```

Two impls:

- `SigstoreSigner` / `SigstoreVerifier` using the `sigstore` crate
  (cosign-bundle compatible). Backed by a `KeyProvider` that resolves
  `cosign://<name>` → PEM bytes from Vault Transit (reuse the existing
  `VaultConfig` at `crates/nebula-common/src/config.rs:322`) or static
  PEM file.
- `NotationStub` returning `SignError::NotImplemented` for now — keeps
  the trait pluggable.

Storage convention (cosign):

- Signed manifest: `sha256:<digest>` already at
  `<tenant>/<project>/<repo>/manifests/<digest>` (see
  `manifest_path` helper in `crates/nebula-common/src/storage.rs:18`).
- Signature artifact: pushed as a normal manifest at tag
  `sha256-<hex>.sig` in the same repo. This is the cosign convention and
  the OCI 1.1 referrers API resolves it correctly without registry-side
  knowledge.

Verification hook lives in `get_manifest` after the bytes are loaded
(today `crates/nebula-registry/src/main.rs:838`). Order:

1. Resolve manifest bytes (existing path).
2. If `policy.signature_required` for this repo, fetch
   `sha256-<digest>.sig` artifact, run `Verifier::verify`, fail with
   `MANIFEST_BLOB_UNKNOWN` if not trusted.
3. Otherwise serve normally.

CLI: `nebulacr sign <ref> [--key vault://transit/cosign-key]`,
`nebulacr verify <ref> [--policy production]`. MCP exposes `sign_image`,
`verify_image`, and `list_signers`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: ImageVerificationPolicy
metadata:
  name: production-must-be-signed
  namespace: tenant-acme
spec:
  tenantRef: acme
  scope:
    projects: ["prod", "release"]
    repositories: ["*"]
  required: true
  trustedSigners:
    - kind: Key
      keyRef: vault://transit/cosign-acme-prod
      identityName: build-bot@acme.io
    - kind: Keyless          # v1.1
      issuer: https://token.actions.githubusercontent.com
      subjectPattern: "repo:acme/.+:ref:refs/heads/main"
  rekor:
    requireTransparencyLogEntry: false   # v1.1 flips default
    rekorUrl: https://rekor.sigstore.dev
  onViolation: block          # block | warn | log
```

No change to `Project` or `Tenant`.

## d. New HTTP routes

| Method | Path                                                                                                | Auth scope               | Body / response                              |
| ------ | --------------------------------------------------------------------------------------------------- | ------------------------ | -------------------------------------------- |
| POST   | `/v2/{tenant}/{project}/{repo}/signatures/{digest}` (and 2-seg variant `/v2/{project}/{repo}/...`)  | `repo:push`              | Cosign `.sig` body; returns `201 Location:`  |
| GET    | `/v2/{tenant}/{project}/{repo}/signatures/{digest}`                                                 | `repo:pull`              | List of signature artifact descriptors      |
| GET    | `/v2/{tenant}/{project}/{repo}/referrers/{digest}`                                                  | `repo:pull`              | OCI 1.1 referrers index                      |
| POST   | `/v2/_verify`                                                                                       | `repo:pull` on subject   | `{ ref, policy }` → `{ trusted, signers }`   |

Existing `put_manifest` (`crates/nebula-registry/src/main.rs:886`) is the
mount point for the post-sign verification hook on tagged pushes when the
referenced manifest is itself a signature.

## e. Storage / Postgres schema

```sql
-- 0004_signatures.sql
CREATE TABLE signatures (
    id              UUID PRIMARY KEY,
    subject_digest  TEXT NOT NULL,           -- sha256:... of signed manifest
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    repository      TEXT NOT NULL,
    signature_digest TEXT NOT NULL,          -- sha256:... of .sig artifact
    signer_identity TEXT,                    -- key fingerprint or OIDC sub
    signature_type  TEXT NOT NULL,           -- 'cosign-key' | 'cosign-keyless' | 'notation'
    rekor_log_index BIGINT,                  -- nullable, set when keyless
    signed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (subject_digest, signature_digest)
);
CREATE INDEX signatures_subject_idx ON signatures (subject_digest);
CREATE INDEX signatures_tenant_repo_idx ON signatures (tenant, project, repository);

CREATE TABLE verification_policies (
    id            UUID PRIMARY KEY,
    name          TEXT NOT NULL,
    tenant        TEXT NOT NULL,
    spec          JSONB NOT NULL,            -- mirrors the CRD spec
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    on_violation  TEXT NOT NULL DEFAULT 'block',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, name)
);
```

The signature artifact bytes themselves live in object storage at the
existing manifest path; only metadata is in Postgres. A controller
reconciler keeps `verification_policies` rows in lockstep with the CRD.

## f. Failure modes

- **Vault / KMS unreachable during sign.** Return `503` with
  `Retry-After: 5`; do NOT degrade to unsigned. Push of the signature
  artifact returns the same error.
- **Verifier fetches policy from Postgres miss.** Treat as
  `required=false` with a `WARN` log and a `nebulacr_signing_policy_miss_total`
  counter — fail open is the safe default; ops alerts on the counter.
- **Rekor unreachable** when `requireTransparencyLogEntry=true`. Fail
  closed. Cache the last 1024 verified `(digest, log_index)` pairs in
  Redis with 1 h TTL to ride out brief outages.
- **Verification policy contradicts `WARN` mode.** `onViolation=warn`
  emits an audit row and a metric but serves the manifest.

## g. Migration story

`[signing]` section of `nebulacr.toml`:

```toml
[signing]
enabled = false              # default OFF; flip to true to enable
require_for_pull = false
default_key_ref = "vault://transit/cosign-key"
```

When `enabled = false`, the `signatures` table is created but never read;
the verification middleware is not mounted. Existing clients (Docker,
crane, podman) work unchanged. To migrate: deploy with
`enabled = true`, push signatures for existing images via
`nebulacr sign --bulk`, then flip `require_for_pull = true`.

## h. Test plan

| Layer                | Where                                                       | Mocks / reality                                    |
| -------------------- | ----------------------------------------------------------- | -------------------------------------------------- |
| Trait contracts      | `crates/nebula-signing/tests/`                              | Vector tests against fixed PEM keys                |
| Sigstore round-trip  | `crates/nebula-signing/tests/sigstore_roundtrip.rs`         | In-memory key, no Rekor                            |
| Vault key provider   | `crates/nebula-signing/tests/vault_provider.rs`             | `vault` testcontainer                              |
| Manifest hook        | `crates/nebula-registry/tests/sign_pull.rs`                 | Real Postgres + filesystem store                   |
| CRD reconciliation   | `crates/nebula-controller/tests/imageverificationpolicy.rs` | `kube` client against `kind` cluster (CI-only job) |
| End-to-end           | `tests/e2e/sign_verify.sh`                                  | Push image → sign → pull from another node         |

## i. Implementation slice count

4 slices, ~4 weeks:

1. `nebula-signing` crate skeleton, `Signer`/`Verifier` traits, in-memory
   keyed impl, unit tests.
2. Sigstore-rs integration, Vault Transit key provider, `nebulacr sign`
   CLI subcommand.
3. `signatures` table + reconciler, `POST/GET /signatures/{digest}` and
   referrers API, audit hook (depends on 005).
4. `ImageVerificationPolicy` CRD + verify-on-pull middleware in
   `get_manifest`, integration tests, Helm flag, docs.
