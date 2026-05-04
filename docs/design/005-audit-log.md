# 005 — Append-Only Hash-Chained Audit Log

> **Summary.** Replace the in-memory ring buffer at
> `crates/nebula-registry/src/audit.rs:43` with a Postgres-backed,
> hash-chained, append-only log. Every state-changing op (push, delete,
> sign, promote, policy change, login, key rotation) emits one row;
> each row's hash is `sha256(prev_hash || canonical_json(this_row))`.
> Periodic export to S3 in JSONL with a Merkle root checkpoint enables
> long-term retention and tamper-evidence.

## a. Problem statement

ACR has Azure Activity Log; Nexus has the audit log feature. NebulaCR's
current audit (`crates/nebula-registry/src/audit.rs`) is a `VecDeque`
with `MAX_EVENTS = 10_000` capped — restarting drops history; an
attacker with shell access can mutate freely; nothing exports. This is
table-stakes for SOC 2 / ISO 27001.

## b. Proposed approach

New crate `nebula-audit` exposing one trait and two impls:

```rust
// crates/nebula-audit/src/lib.rs
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn append(&self, event: AuditEvent) -> Result<EventId, AuditError>;
    async fn query(&self, q: AuditQuery) -> Result<Vec<AuditRow>, AuditError>;
    async fn verify_chain(&self, from: EventId, to: EventId) -> Result<ChainVerdict, AuditError>;
}

pub struct PgChainedAudit { pool: PgPool, hmac_key: SecretBytes }
pub struct InMemoryAudit { /* dev-only fallback */ }

#[derive(Serialize, Deserialize)]
pub struct AuditEvent {
    pub at: DateTime<Utc>,
    pub category: Category,        // Auth | Push | Pull | Delete | Sign |
                                   // Promote | Policy | Key | Admin
    pub action: String,            // free-form within category
    pub actor: Actor,              // {sub, role, source_ip, ua}
    pub subject: Option<Subject>,  // {tenant, project, repo, ref, digest}
    pub outcome: Outcome,          // Success | Failure { code }
    pub attributes: Map<String, Value>,
}
```

The chain: each row stores `prev_hash` + `row_hash` where
`row_hash = sha256(hmac(hmac_key, prev_hash || canonical_json(event)))`.
HMAC keyed with a per-tenant secret in Vault — even an attacker with
DB write access cannot forge a valid hash without the key. Verifier
walks rows in order, asserts each link.

Wiring: replace every `state.audit_log.record(...)` call in
`crates/nebula-registry/src/main.rs` (e.g. lines 866, 1023, 1129) with
`state.audit.append(...)`. Adapter shim keeps `RegistryAuditEvent` for
backwards-compat for one minor version, then delete.

Sampling: read ops (`manifest.pull`, `blob.pull`) optional — controlled
by `[audit] sample_pulls = 0.01`. Default 0 (off — write ops only).

Export job (controller-managed): every hour, dump rows since last
checkpoint to `s3://<bucket>/audit/<tenant>/<yyyy>/<mm>/<dd>/<hh>.jsonl.zst`,
write a checkpoint row containing the Merkle root over the dumped
range. Operators rotate hmac_key by inserting a "key rotation" event
with the new key id; subsequent rows hash with the new key. Old chain
remains verifiable with the old key.

CLI: `nebulacr audit query --since 1h --actor user@x`,
`nebulacr audit export --to s3://...`, `nebulacr audit verify --range
<from>:<to>`. MCP: `query_audit`, `verify_audit_chain`.

## c. New/changed CRDs

None. Audit destinations and key references are config-driven, not
cluster-driven, because they touch secrets that don't belong in
`kubectl get`.

## d. New HTTP routes

| Method | Path                                | Auth scope        | Notes                                            |
| ------ | ----------------------------------- | ----------------- | ------------------------------------------------ |
| GET    | `/v2/_audit`                        | `tenant:admin`    | Query: `?since=&actor=&category=&limit=`         |
| GET    | `/v2/_audit/{id}`                   | `tenant:admin`    | Single row + chain links                         |
| POST   | `/v2/_audit/verify`                 | `tenant:admin`    | Body `{from, to}` → `ChainVerdict`               |
| POST   | `/v2/_audit/export`                 | `tenant:admin`    | Trigger ad-hoc export, returns S3 URL            |

Existing `/api/audit` dashboard route at
`crates/nebula-registry/src/main.rs:2908` is rewired to the new sink.

## e. Storage / Postgres schema

```sql
-- 0008_audit_log.sql
CREATE TABLE audit_log (
    id            BIGSERIAL PRIMARY KEY,
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant        TEXT,                       -- nullable for cross-tenant ops
    category      TEXT NOT NULL,
    action        TEXT NOT NULL,
    actor_sub     TEXT NOT NULL,
    actor_ip      INET,
    actor_ua      TEXT,
    subject       JSONB,
    outcome       TEXT NOT NULL,              -- 'success' | 'failure'
    error_code    TEXT,
    attributes    JSONB NOT NULL DEFAULT '{}',
    prev_hash     BYTEA,                      -- 32 bytes
    row_hash      BYTEA NOT NULL,             -- 32 bytes
    hmac_key_id   TEXT NOT NULL
);
CREATE INDEX audit_log_at_idx       ON audit_log (at DESC);
CREATE INDEX audit_log_tenant_at_idx ON audit_log (tenant, at DESC);
CREATE INDEX audit_log_actor_at_idx ON audit_log (actor_sub, at DESC);
CREATE INDEX audit_log_subject_idx  ON audit_log USING GIN (subject jsonb_path_ops);

CREATE TABLE audit_checkpoints (
    id           BIGSERIAL PRIMARY KEY,
    range_from   BIGINT NOT NULL REFERENCES audit_log(id),
    range_to     BIGINT NOT NULL REFERENCES audit_log(id),
    merkle_root  BYTEA NOT NULL,
    exported_to  TEXT,                       -- s3://...
    at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- DB-level tamper-evidence: deny UPDATE / DELETE on audit_log to
-- non-superuser roles via REVOKE in the migration.
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;
```

The `BIGSERIAL` ordering is the chain order; `row_hash` is computed at
insert time inside a Postgres function `audit_append(...)` so the
chain cannot be broken even by a misbehaving client.

## f. Failure modes

- **Postgres down.** Writes that must audit (push, sign, promote)
  return 503. We do not silently drop audit events. For high-traffic
  pull (sampled 1%) we drop and increment `nebulacr_audit_dropped_total`.
- **HMAC key rotation in flight.** New events use `hmac_key_id = "v2"`;
  verifier must hold both keys during overlap window. Stored in
  `audit_keys` table (separate, can be dumped to backup easily).
- **Export to S3 fails.** Checkpoint not written; next run retries from
  last checkpoint. Audit rows themselves are not lost — they live in
  Postgres until export succeeds.
- **Chain verification fails.** Returns the row id of the first broken
  link, the expected hash, and the actual hash. Operators investigate;
  a positive `verify_chain` failure is a security incident.

## g. Migration story

`[audit]` section, `backend = "memory"` (default — preserves current
behaviour) or `"postgres"` (new). When `"postgres"` and the schema is
absent, the registry refuses to start with a clear error. The shim at
`crates/nebula-registry/src/audit.rs` now wraps both impls; existing
callers see no API change for a release.

## h. Test plan

| Layer            | Where                                              | Notes                                |
| ---------------- | -------------------------------------------------- | ------------------------------------ |
| Chain integrity  | `crates/nebula-audit/tests/chain.rs`               | Postgres testcontainer; tamper test  |
| HMAC rotation    | `crates/nebula-audit/tests/rotation.rs`            | Two keys, mid-stream rotation        |
| Export round-trip | `crates/nebula-audit/tests/export.rs`             | S3 testcontainer (LocalStack)        |
| Registry hooks   | `crates/nebula-registry/tests/audit_e2e.rs`        | Push image, assert exact event row   |
| Concurrent append | `crates/nebula-audit/tests/concurrent.rs`         | 100 parallel appends, chain valid    |

## i. Implementation slice count

3 slices, ~3 weeks:

1. `nebula-audit` crate, schema, `PgChainedAudit` impl, append + query.
2. Wire into all `record(...)` call sites in `nebula-registry`,
   `nebula-auth`, `nebula-controller`. Add HTTP routes.
3. Export job, Merkle checkpoint, key rotation, CLI verify, dashboard
   page wiring.
