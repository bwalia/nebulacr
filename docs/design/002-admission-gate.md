# 002 — Pull-Time Admission Gate (Registry Firewall)

> **Summary.** A pull-time middleware in `get_manifest` that consults the
> scanner's existing `PolicyEvaluation` plus the new signing policy and
> blocks/warns/allows the pull. Decisions cache in Redis with a sub-minute
> TTL keyed by `(digest, policy_id)`. First-pull-without-scan triggers a
> synchronous scan with a configurable wait budget; if the budget is
> exceeded, the policy's `onUnknown` mode decides.

## a. Problem statement

ACR has Microsoft Defender admission control; Nexus IQ has the firewall
quarantine. NebulaCR has a scanner that runs on push
(`crates/nebula-registry/src/main.rs:980-998`) but no enforcement on
pull — a vulnerable image scanned 10 min ago is still served. Admission
gating is the actual security feature; everything else is metadata.

## b. Proposed approach

New module `crates/nebula-registry/src/admission.rs`. Single function:

```rust
pub async fn evaluate(
    state: &AppState,
    claims: &TokenClaims,
    subject: &Subject,           // tenant/project/repo/digest
) -> Result<AdmissionVerdict, RegistryError>;

pub enum AdmissionVerdict {
    Allow,
    Warn { reason: String },
    Block { reason: String, code: &'static str },
}
```

Hook point: `get_manifest` at `crates/nebula-registry/src/main.rs:838`,
right after manifest bytes are loaded but before audit + response. For
HEAD, the same evaluator runs but returns `Allow` for warn-mode (HEAD
doesn't carry a body to attach reasoning to).

The evaluator orchestrates four sources, in order:

1. **Redis decision cache** — key `admit:{digest}:{policy_id}`,
   30-second TTL. Cuts steady-state pull latency to one Redis GET.
2. **Scanner result** — `ScanResultStore::get(digest)` from
   `crates/nebula-scanner/src/store.rs:21` (existing). If present, run
   the existing `PolicyEvaluation` (`crates/nebula-scanner/src/policy.rs:39`)
   against the new admission `PolicyCRD.severityThreshold`.
3. **Signature check** — if 001 enabled and `policy.signatureRequired`,
   delegate to `nebula_signing::Verifier`.
4. **Scan-on-first-pull fallback** — if no scanner result, behaviour
   depends on `policy.onUnknown`:
   - `block` (default): return `MANIFEST_UNVERIFIED` 403.
   - `scan`: `state.scanner_queue.enqueue_priority(...)` (new helper —
     see migration in `nebula-scanner/src/queue.rs`), wait up to
     `policy.scan_wait_secs` (default 5), poll Redis store; if it
     completes evaluate normally, otherwise apply `onTimeout`.
   - `allow`: serve, emit `nebulacr_admit_unknown_total`.

Suppressions are honoured automatically — `Policy::evaluate` already
filters suppressed CVEs (`crates/nebula-scanner/src/policy.rs:41`).

The `bypass-admission` permission (new `Action::BypassAdmission`,
extends `crates/nebula-common/src/models.rs:95`) lets break-glass tokens
skip the gate for incident response. Always audited.

CLI: `nebulacr admit test <ref>` runs the evaluator dry; `nebulacr admit
override <ref> --reason "..."` issues a one-shot bypass token. MCP:
`evaluate_admission`, `request_bypass`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: AdmissionPolicy
metadata:
  name: prod-block-criticals
  namespace: tenant-acme
spec:
  tenantRef: acme
  scope:
    projects: ["prod"]
    repositories: ["*"]
  signatureRequired: true
  severityThreshold:
    block:
      critical: ">0"
      high: ">5"
    warn:
      medium: ">20"
  onUnknown: scan          # block | scan | allow
  onTimeout: block         # block | warn | allow
  scanWaitSecs: 5
  bypassPermission: bypass-admission
```

The scanner's existing YAML `Policy` (`crates/nebula-scanner/src/policy.rs:20`)
is reused as the inner `severityThreshold`; this CRD is a thin envelope
that adds scope + signature + on-unknown semantics.

## d. New HTTP routes

| Method | Path                                       | Auth scope         | Notes                                            |
| ------ | ------------------------------------------ | ------------------ | ------------------------------------------------ |
| POST   | `/v2/_admit/test`                          | `tenant:manage`    | Body `{ref, policyName}` → `AdmissionVerdict`    |
| POST   | `/v2/_admit/bypass`                        | `tenant:admin`     | Issue 5-min bypass token, audited                |
| GET    | `/v2/_admit/policies`                      | `tenant:read`      | List active policies                             |

The actual gate runs invisibly inside `GET /v2/.../manifests/{ref}` and
returns the OCI standard error `MANIFEST_UNVERIFIED` (new code added to
`crates/nebula-common/src/errors.rs`). On `block` the response includes
a `WWW-NebulaCR-Reason` header with the human-readable cause.

## e. Storage / Postgres schema

```sql
-- 0005_admission_policies.sql
CREATE TABLE admission_policies (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    tenant      TEXT NOT NULL,
    spec        JSONB NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, name)
);

CREATE TABLE admission_decisions (
    id          BIGSERIAL PRIMARY KEY,
    decided_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    digest      TEXT NOT NULL,
    policy_id   UUID NOT NULL REFERENCES admission_policies(id),
    verdict     TEXT NOT NULL,                    -- 'allow' | 'warn' | 'block'
    reason      TEXT,
    subject     TEXT NOT NULL,                    -- JWT sub
    request_id  TEXT NOT NULL
);
CREATE INDEX admission_decisions_digest_time_idx
    ON admission_decisions (digest, decided_at DESC);
```

Decisions are kept 90 days for forensic queries, then archived via the
audit log export job (see 005). The Redis short-term cache is the
hot path; Postgres is the audit trail.

## f. Failure modes

- **Redis down.** Skip cache; evaluate fresh every time. Already-spent
  budget on Postgres queries is acceptable; pull latency degrades but
  doesn't fail. Never fail closed on Redis alone.
- **Postgres down (scanner store unreachable).** `onUnknown` semantics
  apply — under `block` the registry returns 503; under `allow` it
  serves and increments a metric.
- **Scan-on-pull starvation.** If the queue depth exceeds
  `policy.scanWaitSecs * worker_throughput`, all pulls would block.
  Mitigation: `enqueue_priority` enforces a per-tenant cap; over the cap
  it returns immediately and `onTimeout` fires.
- **Signing policy missing.** If 001 is disabled but a policy still
  sets `signatureRequired: true`, controller validation rejects the CRD
  with a clear webhook error.

## g. Migration story

`[admission]` section, `enabled = false` ships a no-op gate. Existing
deployments see zero behaviour change. To migrate: enable, write an
`AdmissionPolicy` with `onViolation: warn` for a week, monitor
`nebulacr_admit_warn_total`, then flip to `block`.

## h. Test plan

| Layer            | Where                                              | Notes                                |
| ---------------- | -------------------------------------------------- | ------------------------------------ |
| Pure evaluator   | `crates/nebula-registry/tests/admission_unit.rs`   | Mocked scanner store, mocked Redis   |
| With real scan   | `crates/nebula-registry/tests/admission_e2e.rs`    | Postgres + Redis testcontainers      |
| Bypass audit     | `crates/nebula-registry/tests/admission_bypass.rs` | Asserts audit row written            |
| Scan-on-first    | `crates/nebula-registry/tests/scan_on_first.rs`    | Force scanner queue with delay       |
| CRD validation   | `crates/nebula-controller/tests/admission_crd.rs`  | webhook rejects `signatureRequired`  |
|                  |                                                    | when signing module disabled         |

## i. Implementation slice count

3 slices, ~3 weeks:

1. `admission.rs` evaluator + Redis cache + the `block`/`allow` paths,
   integrating existing scanner result store.
2. `AdmissionPolicy` CRD + reconciler + `onUnknown` scan-on-pull with
   priority queue helper in `nebula-scanner/src/queue.rs`.
3. Bypass permission, `_admit/test` endpoint, audit integration (depends
   on 005 if available; otherwise writes to in-memory ring).
