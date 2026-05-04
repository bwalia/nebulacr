# 008 — Customer-Managed Key (CMK) Envelope Encryption At Rest

> **Summary.** Per-tenant Key Encryption Key (KEK) lives in an external
> KMS behind a new `KeyProvider` trait (AWS KMS, GCP KMS, Azure Key
> Vault, HashiCorp Vault). Each blob gets a fresh Data Encryption Key
> (DEK); blobs are AES-256-GCM encrypted before storage; the wrapped
> DEK is stored alongside the blob digest in Postgres. Key rotation
> re-wraps DEKs without re-encrypting blobs — fast and bandwidth-free.
>
> **Constraint discovered while reading the code.** There is no
> `Storage` trait in `nebula-common` (`crates/nebula-common/src/storage.rs`
> exposes only path builders). The registry talks to
> `object_store::ObjectStore` directly (e.g.
> `crates/nebula-registry/src/main.rs:920`). 008 must therefore
> introduce a new wrapping trait — see (b).

## a. Problem statement

ACR has CMK with Azure Key Vault; Nexus has IQ-managed encryption.
NebulaCR encrypts in transit (TLS) and relies on backend defaults at
rest (S3 SSE-S3, etc.) — fine for many, insufficient for FedRAMP/
ITAR/HIPAA where the customer must hold the key. Without CMK,
NebulaCR can't enter regulated procurement.

## b. Proposed approach

New crate `nebula-crypto` introducing the missing Storage trait
abstraction:

```rust
// crates/nebula-crypto/src/lib.rs
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Wrap a plaintext DEK with the tenant's KEK. Returns ciphertext
    /// blob + key id.
    async fn wrap(&self, tenant_id: Uuid, dek: &[u8]) -> Result<WrappedDek, KeyErr>;
    async fn unwrap(&self, w: &WrappedDek) -> Result<Zeroizing<Vec<u8>>, KeyErr>;
    /// Rotate the KEK. Returns the new key id; existing wrapped DEKs
    /// stay valid until re-wrapped.
    async fn rotate(&self, tenant_id: Uuid) -> Result<KeyId, KeyErr>;
}

pub struct WrappedDek {
    pub key_id:     KeyId,
    pub algorithm:  WrapAlgo,    // AES-GCM-256-WRAP | RSA-OAEP-256
    pub ciphertext: Vec<u8>,
    pub nonce:      [u8; 12],
}

// New, sits between handlers and object_store.
#[async_trait]
pub trait EncryptedStore: Send + Sync {
    async fn put_blob(&self, tenant: Uuid, path: &Path, data: Bytes) -> Result<BlobMeta, StorErr>;
    async fn get_blob(&self, tenant: Uuid, path: &Path) -> Result<Bytes, StorErr>;
}
```

Impls:

- `AwsKmsProvider`, `GcpKmsProvider`, `AzureKeyVaultProvider`,
  `VaultTransitProvider` (reuses
  `crates/nebula-common/src/config.rs:322`), `LocalDevProvider`
  (file-on-disk, dev only, refuses to start if `enabled=true` in prod).
- `EnvelopeEncryptedStore<S: ObjectStore>` wraps any existing
  `object_store::ObjectStore`. On `put_blob`: generate DEK,
  AES-256-GCM encrypt, persist ciphertext to inner store, persist
  `WrappedDek` to Postgres `wrapped_deks` keyed by digest.

Wiring: in `main.rs` where `state.store` (raw ObjectStore) is used for
blob/manifest IO (e.g. lines 920, 1147–1196), introduce a new
`state.encrypted_store: Option<Arc<dyn EncryptedStore>>`. When CMK is
enabled, blob handlers route through it; when disabled, raw store
path is unchanged. Manifests are not encrypted — they're public-by-
content-addressing already and contain only digests/sizes.

Key rotation: `nebulacr key rotate --tenant acme` calls
`KeyProvider::rotate`, then a background `rewrap_dek` job iterates
`wrapped_deks WHERE key_id = old_id`, unwraps with old, wraps with
new, atomically updates the row. Blobs are untouched.

CLI: `nebulacr key list`, `nebulacr key rotate <tenant>`,
`nebulacr key migrate --from <provider> --to <provider>`. MCP:
`rotate_kek`, `list_wrapped_deks`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: TenantKey
metadata:
  name: acme-cmk
  namespace: tenant-acme
spec:
  tenantRef: acme
  provider: aws-kms                       # aws-kms | gcp-kms | azure-kv | vault
  awsKms:
    keyArn: arn:aws:kms:us-east-1:123:key/abcd-efgh
    region: us-east-1
  rotation:
    cron: "0 3 1 */3 *"                   # quarterly
    autoRewrap: true
status:
  currentKeyId: abcd-efgh
  lastRotatedAt: 2026-04-01T03:00:00Z
  wrappedDekCount: 12345
```

The controller pulls credentials from a referenced `Secret` for
provider auth; the spec never embeds them.

## d. New HTTP routes

| Method | Path                            | Auth scope        | Notes                                       |
| ------ | ------------------------------- | ----------------- | ------------------------------------------- |
| POST   | `/v2/_keys/{tenant}/rotate`     | `tenant:admin`    | Trigger rotation, returns new key id        |
| GET    | `/v2/_keys/{tenant}`            | `tenant:read`     | Current key id, last rotated, DEK count    |
| POST   | `/v2/_keys/{tenant}/rewrap`     | `tenant:admin`    | Body `{batchSize}` → kicks rewrap job       |
| GET    | `/v2/_keys/{tenant}/rewrap/{id}` | `tenant:admin`   | Rewrap job status                           |

Encryption is invisible to OCI clients — the existing blob and
manifest routes route through the encrypted store transparently.

## e. Storage / Postgres schema

```sql
-- 0010_cmk.sql
CREATE TABLE tenant_keys (
    tenant_id     UUID PRIMARY KEY,
    provider      TEXT NOT NULL,                  -- 'aws-kms' | ...
    current_key_id TEXT NOT NULL,
    spec          JSONB NOT NULL,                 -- mirrors the CRD
    rotated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE wrapped_deks (
    digest        TEXT PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenant_keys(tenant_id),
    key_id        TEXT NOT NULL,                  -- which KEK wrapped this DEK
    algorithm     TEXT NOT NULL,
    nonce         BYTEA NOT NULL,
    ciphertext    BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rewrapped_at  TIMESTAMPTZ
);
CREATE INDEX wrapped_deks_tenant_keyid_idx
    ON wrapped_deks (tenant_id, key_id);

CREATE TABLE rewrap_jobs (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    from_key_id   TEXT NOT NULL,
    to_key_id     TEXT NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at   TIMESTAMPTZ,
    deks_total    INT NOT NULL DEFAULT 0,
    deks_done     INT NOT NULL DEFAULT 0,
    state         TEXT NOT NULL                  -- 'pending' | 'running' | 'done' | 'failed'
);
```

## f. Failure modes

- **KMS unavailable on PUT.** Return 503 with `Retry-After: 5`; do
  not store unencrypted. Push fails — clients retry naturally.
- **KMS unavailable on GET.** Same — pulls fail with 503. Mitigation:
  per-pod LRU cache of `(digest → DEK plaintext)` with strict TTL
  (default 60 s) and `Zeroizing` so cache eviction wipes memory. Cap
  size at 10 k entries.
- **DEK row missing for an existing blob.** Means encryption was
  enabled mid-flight without re-encryption. Return 500 with explicit
  message; admin runs `nebulacr key migrate --to <provider>` which
  encrypts existing plaintext blobs in place and writes DEK rows.
- **Rotation crashes mid-rewrap.** `rewrap_jobs` resumes from
  `MAX(rewrapped_at)`. Old key id stays valid until job completes —
  do not delete the old KEK in KMS until `state = 'done'`.
- **Provider migration.** New impl + dual-write window: writes go to
  both, reads prefer new, then a one-time backfill, then drop old.

## g. Migration story

`[encryption]` section, `enabled = false` (default). When false,
`encrypted_store` is `None` and all blob IO goes through the existing
raw `state.store` path — zero behaviour change. To enable: deploy with
`enabled = true`, create `TenantKey` CRD per tenant, run
`nebulacr key migrate --tenant acme` to encrypt existing blobs (a
streamed re-write — slow but resumable; uses `pending_uploads` table
from 004 to lock the operation).

## h. Test plan

| Layer              | Where                                                 | Notes                                            |
| ------------------ | ----------------------------------------------------- | ------------------------------------------------ |
| Round-trip         | `crates/nebula-crypto/tests/roundtrip.rs`             | `LocalDevProvider`; encrypt then decrypt 1 GB    |
| AWS KMS            | `crates/nebula-crypto/tests/aws_kms.rs`               | LocalStack KMS                                   |
| Vault Transit      | `crates/nebula-crypto/tests/vault_transit.rs`         | Vault testcontainer                              |
| Rotation + rewrap  | `crates/nebula-crypto/tests/rotation.rs`              | Two key ids, batch rewrap, verify all readable   |
| Push/pull e2e      | `crates/nebula-registry/tests/cmk_e2e.rs`             | Real registry with encrypted store enabled       |
| KMS-down failure   | `crates/nebula-crypto/tests/kms_outage.rs`            | Simulated 503; assert push/pull both 503         |

## i. Implementation slice count

4 slices, ~4 weeks:

1. `nebula-crypto` crate, `KeyProvider` + `EncryptedStore` traits,
   `LocalDevProvider`, schema, round-trip tests.
2. `EnvelopeEncryptedStore` + integration into `put_blob`/`get_blob`/
   `complete_blob_upload` paths in `main.rs`. Provider trait impls
   (start with Vault Transit, add AWS KMS).
3. `TenantKey` CRD + reconciler + rotation + rewrap job + CLI.
4. Migration tool (`nebulacr key migrate`), GCP/Azure providers,
   docs, Helm wiring, dashboard key list page (007 dependency).
