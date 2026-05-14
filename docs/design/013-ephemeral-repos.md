# 013 — Ephemeral Repositories & TTL Tags (PR-Build Lifecycle)

> **Summary.** A "PR build" namespace where every push gets a TTL,
> every tag is auto-deleted at expiry, and the whole repo evaporates
> when its source PR closes. Built on top of 003 (tag-state) and
> 004/009 (GC). One annotation on push (`X-NebulaCR-TTL: 7d`) is
> enough; CI/CD wiring is `nebulacr ci tag --pr 1234 → ephemeral`.

## a. Problem statement

Every CI pipeline pushes a per-PR / per-commit image and 99 % of
those tags are abandoned within a week, but they sit in the
registry forever — Nexus and ACR both stop only at retention rules
and "max tag count" rules that operators forget to tune. The result
is registries where 80 % of stored bytes are PR scratch. Operators
either run aggressive retention (which stomps on real release
tags) or do nothing (and pay the storage bill). NebulaCR can model
ephemerality as a first-class property: the tag *knows* it is
ephemeral, the registry *knows* when to drop it, and CI doesn't
need a separate cleanup pipeline.

## b. Proposed approach

Two lightweight features:

### 1. TTL tags

Any tag can carry a TTL. On push, clients set
`X-NebulaCR-TTL: <duration>` (e.g. `7d`, `12h`, `2026-06-01T00:00Z`).
The registry stores the expiry on the `tags` table (the same one
003 already extends with state). A reaper removes expired tags via
the same code path as a normal `DELETE /v2/<name>/manifests/<tag>`,
which means audit, GC refcount decrement, and signing teardown all
flow naturally.

```rust
// crates/nebula-registry/src/ttl.rs
pub struct TtlReaper { db: PgPool, registry: Arc<RegistryHandle> }

impl TtlReaper {
    /// SELECT tag, repository FROM tags WHERE expires_at < NOW()
    /// FOR UPDATE SKIP LOCKED LIMIT 500. Issue DELETE manifest for each.
    pub async fn run(self) -> Result<Infallible, TtlError>;
}
```

Hook into `put_manifest` at
`crates/nebula-registry/src/main.rs:886` to read the header and
write `expires_at` on the `tags` row.

### 2. Ephemeral repositories

A repository can be marked `ephemeral` at create time. Every tag
inherits a default TTL; the entire repo is reaped when:

- All tags expire AND `expireOnEmpty: true` (default), OR
- A linked SCM event closes the PR (webhook from GitHub /
  GitLab / Bitbucket → `POST /v2/_ephemeral/notify`), OR
- The repo's `expiresAt` is past.

CI flow:

```bash
# At PR open
nebulacr ci tag --pr 1234 --repo acme/prod/api/pr-1234 --ttl 7d
# This calls POST /v2/_ephemeral/repos and gets back a scoped token.

# At PR push
docker push registry.example.com/acme/prod/api/pr-1234:abc1234

# At PR close (handled by webhook from GitHub)
# All tags & manifests deleted, refcounts decrement, GC reaper picks up.
```

The CLI subcommand `nebulacr ci tag` is opinionated: it composes
the right TTL header, scopes a token to push only to that one
repo, and registers the SCM webhook in one shot.

CLI: `nebulacr ttl set <ref> --ttl 7d`, `nebulacr ttl extend <ref>
--by 7d`, `nebulacr ephemeral list`, `nebulacr ephemeral close
<repo>`. MCP: `set_ttl`, `extend_ttl`, `close_ephemeral_repo`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Repository
metadata:
  name: api-pr-1234
spec:
  projectRef: prod
  ephemeral:
    enabled: true
    defaultTtl: 7d
    expireOnEmpty: true
    scmLink:
      provider: github            # github | gitlab | bitbucket
      pr: "https://github.com/acme/api/pull/1234"
      webhookSecretRef:
        name: gh-webhook
        key: secret
    expiresAt: 2026-06-01T00:00Z  # hard cap regardless of activity
```

`Repository` does not currently exist as a CRD — repositories are
implicit from pushes. This proposal adds an *optional* CRD for the
ephemeral case; non-ephemeral repos remain implicit.

Project CRD also gets:

```yaml
spec:
  ephemeralDefaults:
    enabled: false               # opt-in
    pathPattern: 'pr-*'          # repos whose name matches → ephemeral
    defaultTtl: 7d
    maxTtl: 30d                  # pushes asking for more get capped
```

## d. New HTTP routes

| Method | Path                                                    | Auth scope         | Notes                                            |
| ------ | ------------------------------------------------------- | ------------------ | ------------------------------------------------ |
| POST   | `/v2/_ephemeral/repos`                                  | `tenant:write`     | Body = Repository CRD; returns scoped push token |
| GET    | `/v2/_ephemeral/repos`                                  | `tenant:read`      | List ephemeral repos + state                      |
| POST   | `/v2/_ephemeral/notify`                                 | webhook            | SCM webhook (HMAC-validated); marks repo expiring |
| POST   | `/v2/_ephemeral/repos/{repo}/close`                     | `tenant:admin`     | Force-close                                       |
| POST   | `/v2/<name>/manifests/<ref>/ttl`                        | `repo:push`        | Body `{ttl}` → updates `expires_at`              |
| DELETE | `/v2/<name>/manifests/<ref>/ttl`                        | `repo:push`        | Removes expiry (makes permanent)                  |

The push-time `X-NebulaCR-TTL` header is the primary path; the
explicit `/ttl` route is the management plane.

## e. Storage / Postgres schema

```sql
-- 0013_ephemeral.sql

-- Augment 003's tags table:
ALTER TABLE tags
    ADD COLUMN expires_at TIMESTAMPTZ,
    ADD COLUMN ephemeral  BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX tags_expires_idx ON tags (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE ephemeral_repos (
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    repository      TEXT NOT NULL,
    default_ttl_secs BIGINT NOT NULL,
    max_ttl_secs    BIGINT NOT NULL,
    expires_at      TIMESTAMPTZ,
    expire_on_empty BOOLEAN NOT NULL DEFAULT TRUE,
    scm_provider    TEXT,
    scm_pr_url      TEXT,
    scm_state       TEXT NOT NULL DEFAULT 'open',     -- open | closed | merged
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant, project, repository)
);
CREATE INDEX ephemeral_repos_state_idx ON ephemeral_repos (scm_state, expires_at);

CREATE TABLE ttl_reaps (
    id              BIGSERIAL PRIMARY KEY,
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    repository      TEXT NOT NULL,
    tag             TEXT NOT NULL,
    reaped_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason          TEXT NOT NULL                     -- 'ttl' | 'pr-closed' | 'repo-expired'
);
CREATE INDEX ttl_reaps_at_idx ON ttl_reaps (reaped_at DESC);
```

The reaper queries `tags` directly via the partial index — no
separate "expiring soon" table needed.

## f. Failure modes

- **TTL header missing on push to ephemeral repo.** Repo's
  `defaultTtl` applies. If the repo has no default and project has
  no default, push is accepted with no expiry (but a metric flags
  `ephemeral_no_ttl_total` for monitoring).
- **TTL > project's `maxTtl`.** Capped silently to maxTtl; response
  header `X-NebulaCR-TTL-Capped: 30d` informs the client.
- **Reaper deletes a tag a CI is concurrently pulling.** The
  manifest delete sets the tag row to `Quarantined` (003) before
  removing — ongoing pulls complete because they already have
  bytes; new pulls 404. No torn state.
- **SCM webhook spoofed.** HMAC required (`webhookSecretRef`); body
  validated against the SCM provider's signature spec
  (`X-Hub-Signature-256` for GitHub, etc.). Failed validation →
  401 + audit row.
- **PR closed but tags still being actively pulled by old
  deployments.** `expireOnEmpty: false` keeps the repo alive while
  pulls continue (last-pull timestamp tracked in `tags.last_pulled_at`),
  reaped only after `gracePeriod` of inactivity.
- **Operator wants to "save" an ephemeral repo's tag.** `nebulacr
  ttl extend <ref> --by 30d --pin` removes the ephemeral flag and
  promotes to a normal tag.

## g. Migration story

`[ephemeral] enabled = false` ships a no-op. The TTL header is
ignored on push; existing repos cannot be marked ephemeral. After
enabling, only repos created with `ephemeral: true` are affected.
No retroactive migration of existing scratch tags — operators run
004/009 retention if they want a one-time cleanup.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Reaper             | `crates/nebula-registry/tests/ttl_reaper.rs`           | Push 100 tags with TTL 1s; assert reap     |
| Header parsing     | `crates/nebula-registry/tests/ttl_header.rs`           | Valid + invalid + cap behaviours            |
| SCM webhook        | `crates/nebula-registry/tests/scm_webhook.rs`          | GitHub + GitLab + Bitbucket payloads        |
| HMAC validation    | `crates/nebula-registry/tests/scm_hmac.rs`             | Spoofed payload rejected                    |
| Pull during reap   | `crates/nebula-registry/tests/pull_during_ttl.rs`      | In-flight pull survives                     |
| End-to-end CI flow | `tests/e2e/ephemeral_e2e.sh`                           | Open PR → push → close PR → assert deleted  |

## i. Implementation slice count

3 slices, ~3 weeks:

1. `tags.expires_at` migration + push-time TTL header parsing +
   reaper task. Pure tag-level TTL, no ephemeral repos yet.
2. `ephemeral_repos` table + Repository CRD + `_ephemeral/repos`
   routes + project defaults.
3. SCM webhook handlers (GitHub / GitLab / Bitbucket), `nebulacr ci
   tag` CLI subcommand, MCP tools, e2e test, docs (recipe per CI
   platform).
