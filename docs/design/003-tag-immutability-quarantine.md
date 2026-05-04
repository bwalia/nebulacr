# 003 — Tag Immutability + Quarantine State Machine

> **Summary.** Promote tags from a free-for-all rename target to a
> first-class object with a state machine: `pending → scanning →
> approved | quarantined → promoted`. Immutability is a per-Project
> setting (the field already exists at
> `crates/nebula-controller/src/main.rs:109`). Quarantine blocks pulls
> for everyone except holders of the new `BypassQuarantine` permission.

## a. Problem statement

ACR has tag immutability via repository policies; Nexus has the
quarantine workflow as part of Sonatype Lifecycle. NebulaCR's
`put_manifest` blindly overwrites tag links
(`crates/nebula-registry/src/main.rs:929-942`) — a vulnerable rebuild
under the same tag pollutes downstream pulls. There is no concept of
"this tag is awaiting review". Without a state machine, the admission
gate can only block at pull time, not at push.

## b. Proposed approach

New module `crates/nebula-registry/src/tagstate.rs`. Owning struct:

```rust
pub struct TagStateService { db: PgPool, redis: RedisClient }

#[derive(sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "tag_state", rename_all = "snake_case")]
pub enum TagState {
    Pending,      // pushed, scan not started
    Scanning,     // scanner picked it up
    Approved,     // scan passed admission policy
    Quarantined,  // scan or sig check failed
    Promoted,     // copied to dest project (006), source frozen
}

impl TagStateService {
    pub async fn on_push(&self, t: &TagRef, digest: &str) -> Result<(), Err>;
    pub async fn transition(&self, t: &TagRef, to: TagState, reason: &str) -> Result<(), Err>;
    pub async fn current(&self, t: &TagRef) -> Result<Option<TagRecord>, Err>;
    pub async fn is_immutable(&self, p: &ProjectRef) -> Result<bool, Err>;
}
```

Hook in `put_manifest`:

1. Validate JSON (existing).
2. **Immutability check**: if `Project.spec.immutable_tags == true` AND
   tag already exists AND target digest differs → 409
   `MANIFEST_TAG_IMMUTABLE`.
3. Write blob and tag link (existing path).
4. **Insert tag-state row** as `Pending`. Enqueue scan (existing
   fire-and-forget at line 980 stays).

Hook in `get_manifest`/`head_manifest` (after the body resolves at
`main.rs:838`): if `tag_state.current(...) == Quarantined` and the
caller lacks `BypassQuarantine`, return 451 `MANIFEST_QUARANTINED`. The
admission gate (002) is the body of "approved"; this layer is the
state-machine wrapper.

Worker side: the existing scanner worker
(`crates/nebula-scanner/src/worker.rs`) gets a callback hook so a
completed scan transitions the tag — `Pending → Scanning → Approved`
(if policy passes) or `→ Quarantined`. The transition writes an audit
row.

`BypassQuarantine` is a new `Action` variant in
`crates/nebula-common/src/models.rs:95`. Granted only to roles with
explicit `bypass-quarantine` access policy (no role gets it by default,
not even Admin — admins can grant to themselves, which is auditable).

CLI: `nebulacr tag list --state quarantined`,
`nebulacr tag approve <ref>`, `nebulacr tag quarantine <ref> --reason
"..."`. MCP: `transition_tag_state`, `list_tag_state`.

## c. New/changed CRDs

No new CRD. The `Project` CRD already exposes `immutable_tags` at
`crates/nebula-controller/src/main.rs:109`. We add one optional field:

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Project
metadata:
  name: prod
  namespace: tenant-acme
spec:
  tenantRef: acme
  displayName: Production
  visibility: private
  immutableTags: true                 # already exists
  quarantineDefault: true             # NEW — new tags start in 'pending'
                                      # and are blocked from pull until approved
  retentionPolicy:                    # already exists
    maxTagCount: 50
```

## d. New HTTP routes

| Method | Path                                                                           | Auth scope            | Notes                                |
| ------ | ------------------------------------------------------------------------------ | --------------------- | ------------------------------------ |
| GET    | `/v2/{tenant}/{project}/{repo}/_tagstate`                                      | `repo:read`           | List of `{tag, state, since}`        |
| GET    | `/v2/{tenant}/{project}/{repo}/_tagstate/{tag}`                                | `repo:read`           | Single record + history              |
| POST   | `/v2/{tenant}/{project}/{repo}/_tagstate/{tag}/approve`                        | `repo:manage`         | Manual override, audited             |
| POST   | `/v2/{tenant}/{project}/{repo}/_tagstate/{tag}/quarantine`                     | `repo:manage`         | Body `{reason}`, audited             |

2-segment paths mirror these. Existing `PUT manifests/{tag}` returns
`409 MANIFEST_TAG_IMMUTABLE` (new error variant in
`crates/nebula-common/src/errors.rs`) when the immutability check fails.

## e. Storage / Postgres schema

```sql
-- 0006_tag_state.sql
CREATE TYPE tag_state AS ENUM (
    'pending', 'scanning', 'approved', 'quarantined', 'promoted'
);

CREATE TABLE tag_records (
    id            UUID PRIMARY KEY,
    tenant        TEXT NOT NULL,
    project       TEXT NOT NULL,
    repository    TEXT NOT NULL,
    tag           TEXT NOT NULL,
    digest        TEXT NOT NULL,
    state         tag_state NOT NULL,
    state_reason  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, project, repository, tag)
);
CREATE INDEX tag_records_state_idx ON tag_records (state, updated_at);

CREATE TABLE tag_transitions (
    id            BIGSERIAL PRIMARY KEY,
    tag_record_id UUID NOT NULL REFERENCES tag_records(id) ON DELETE CASCADE,
    from_state    tag_state,
    to_state      tag_state NOT NULL,
    reason        TEXT,
    actor         TEXT NOT NULL,            -- JWT sub or 'scanner'
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX tag_transitions_record_at_idx ON tag_transitions (tag_record_id, at);
```

`tag_records` is the live view; `tag_transitions` is the history (also
mirrored into the audit log — but kept here for cheap UI rendering).

## f. Failure modes

- **Postgres down on push.** Tag-state insert fails. Configurable: in
  `[tagstate]` `on_db_error = "fail"` or `"degrade"`. Default `fail` —
  better to reject the push than create an unscanned tag. Degrade is
  for emergency fallback.
- **Scanner crashes mid-scan.** Tag stuck in `Scanning`. The scanner
  worker emits a heartbeat row; a sweep job in the controller resets
  records older than `2 × scan_timeout` back to `Pending` and re-enqueues.
- **Immutability race.** Two concurrent pushes to the same tag. Solved
  by `UNIQUE (tenant, project, repository, tag)` + an `ON CONFLICT DO
  NOTHING` insert + post-hoc digest comparison. Loser sees 409.
- **Bypass abuse.** Every bypass is audited (005). Rate-limited per
  subject in `crates/nebula-registry/src/main.rs:331` (existing rate
  limiter), 5/hour by default.

## g. Migration story

`[tagstate]` section with `enabled = false` ships the schema but does
not write rows or read state during pulls. Existing tags continue
overwriting freely. Operators flip on a per-project basis via the CRD —
the controller backfills `tag_records` for existing tags as `Approved`
(grandfathered) on first reconcile.

## h. Test plan

| Layer                | Where                                                  | Notes                                |
| -------------------- | ------------------------------------------------------ | ------------------------------------ |
| State machine        | `crates/nebula-registry/tests/tagstate_unit.rs`        | Postgres testcontainer               |
| Immutability check   | `crates/nebula-registry/tests/immutable_push.rs`       | Real registry, two PUTs              |
| Quarantine pull-block | `crates/nebula-registry/tests/quarantine_pull.rs`     | Real pull, with and without bypass   |
| Scan→approve         | `crates/nebula-scanner/tests/worker_transition.rs`     | Mock scanner result, assert callback |
| Stuck-state sweeper  | `crates/nebula-controller/tests/tag_sweeper.rs`        | Time-skip, assert recovery           |

## i. Implementation slice count

3 slices, ~3 weeks:

1. Schema + `TagStateService` + `on_push` hook + immutability check.
2. `BypassQuarantine` permission, pull-time block, manual approve/
   quarantine routes, CLI subcommands.
3. Scanner worker callback, stuck-state sweeper, project CRD field
   addition, controller backfill, Helm values.
