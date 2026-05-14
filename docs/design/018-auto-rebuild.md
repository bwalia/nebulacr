# 018 — Auto-Rebuild on Base CVE Patch

> **Summary.** When a base image (e.g. `python:3.12-slim`) gets a
> patched re-push that fixes a CVE NebulaCR's scanner has flagged
> downstream, fire a structured webhook to every repo whose images
> use that base. CI receives the event with a payload tailored to
> the build system (GitHub Actions `repository_dispatch`, GitLab
> pipeline trigger, Tekton EventListener, generic webhook). Operators
> who hooked their CI up correctly get the rebuilt image automatically;
> nothing in the registry rebuilds anything itself — we are the
> trigger, not the build farm.

## a. Problem statement

A new CVE drops on `glibc`; Debian publishes a patched
`debian:bookworm-slim`. Every team's nightly base-pull picks it up,
but no team rebuilds their app images on top until somebody opens a
ticket and says "rebuild." Days pass with vulnerable images in
production. Nexus has a paid feature ("Lifecycle Suggested Components")
that approximates this; ACR has nothing native. NebulaCR has the
ingredients — the scanner already knows which packages are in which
image, and the registry knows which manifests reference which base.
Closing the loop is mostly plumbing.

## b. Proposed approach

New module `crates/nebula-scanner/src/rebuild.rs` plus a
`RebuildEmitter` trait so output destinations are pluggable:

```rust
#[async_trait]
pub trait RebuildEmitter: Send + Sync {
    fn id(&self) -> &'static str;          // "github-dispatch" | "gitlab-trigger" | "tekton" | "webhook"
    async fn emit(&self, event: &RebuildEvent) -> Result<(), EmitError>;
}

pub struct RebuildEvent {
    pub trigger: TriggerCause,                          // BasePushed | CveFixed | ScheduledNightly
    pub fixed_cves: Vec<CveId>,
    pub upstream: ImageRef,                              // the parent that changed
    pub downstream: ImageRef,                            // the image that should rebuild
    pub repo_url: Option<String>,                        // SCM repo to rebuild
    pub branch: Option<String>,
    pub workflow: Option<String>,
}
```

Detection pipeline:

1. Scanner SBOM walk already records, for each image, the package
   list. We add a `parent_image` column to `scans` populated by
   parsing the `image config history` (the `created_by` chain often
   includes `FROM debian:bookworm-slim` evidence; for stricter
   fidelity we accept an `org.opencontainers.image.base.name`
   label per OCI annotation).
2. A new `image_lineage` table tracks
   `(child_digest, parent_digest)` pairs. Built incrementally on
   push.
3. When a new push happens AND the pushed image's digest matches a
   known `parent_digest` AND the previous-version of the parent had
   CVEs the new version doesn't, the rebuild detector emits one
   `RebuildEvent` per descendant image still currently tagged.
4. Rate-limited: at most one event per `(downstream_image, day)` to
   avoid CI fan-out storms when 30 images all share `python:3.12-slim`.
5. Each project configures one or more `RebuildSubscription`s
   describing the SCM repo + emitter.

Authentication out: short-lived signed JWTs sent in the webhook
`Authorization` header, signed by NebulaCR's existing JWT key. CI
verifies via the registry's JWKS.

CLI: `nebulacr rebuild subscriptions list/add/remove`,
`nebulacr rebuild trigger <ref> --reason cve-fix --to <subscription>`
(manual fire), `nebulacr lineage show <ref>` (inspect parent chain).
MCP: `list_rebuild_subscriptions`, `trigger_rebuild`, `inspect_lineage`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: RebuildSubscription
metadata:
  name: api-on-base-cve
  namespace: tenant-acme
spec:
  tenantRef: acme
  watch:
    bases:
      - debian:bookworm-slim
      - python:3.12-slim
    descendants: ["acme/prod/api/*"]      # which downstream images to react for
  triggers:
    onCveFix: true
    onBasePush: false                      # noisy; default off
    minSeverityFixed: high                 # only fire if a high+ CVE was fixed
  emitter:
    type: github-dispatch
    repo: acme/api
    workflow: rebuild.yml
    tokenRef:
      name: gh-pat
      key: token
  rateLimit:
    perDownstreamPerDay: 1
```

```yaml
spec:
  emitter:
    type: webhook
    url: https://ci.example.com/hooks/rebuild
    hmacSecretRef:
      name: ci-hmac
      key: secret
```

```yaml
spec:
  emitter:
    type: gitlab-trigger
    project: 12345
    triggerTokenRef:
      name: gl-token
      key: token
    ref: main
```

## d. New HTTP routes

| Method | Path                                                    | Auth scope         | Notes                                            |
| ------ | ------------------------------------------------------- | ------------------ | ------------------------------------------------ |
| POST   | `/v2/_rebuild/trigger`                                  | `tenant:admin`     | Body `{downstream, reason}` → manual fire        |
| GET    | `/v2/_rebuild/events?since=7d`                          | `tenant:read`      | Recent emitter activity                           |
| GET    | `/v2/_rebuild/subscriptions`                            | `tenant:read`      | List active subscriptions                        |
| POST   | `/v2/_rebuild/subscriptions/{name}/test`                | `tenant:admin`     | Send a synthetic event to verify CI wiring       |
| GET    | `/v2/_lineage/{digest}`                                 | `repo:read`        | Parent + ancestor chain, depth-limited           |

## e. Storage / Postgres schema

```sql
-- 0018_auto_rebuild.sql

-- Augment scans table with detected parent ref (best-effort)
ALTER TABLE scans
    ADD COLUMN parent_image_ref TEXT,
    ADD COLUMN parent_digest TEXT;

CREATE TABLE image_lineage (
    child_digest    TEXT NOT NULL,
    parent_digest   TEXT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confidence      TEXT NOT NULL,                  -- 'label' | 'history' | 'inferred'
    PRIMARY KEY (child_digest, parent_digest)
);
CREATE INDEX image_lineage_parent_idx ON image_lineage (parent_digest);

CREATE TABLE rebuild_subscriptions (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    name            TEXT NOT NULL,
    spec            JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, name)
);

CREATE TABLE rebuild_events (
    id                UUID PRIMARY KEY,
    subscription_id   UUID NOT NULL REFERENCES rebuild_subscriptions(id) ON DELETE CASCADE,
    upstream_ref      TEXT NOT NULL,
    downstream_ref    TEXT NOT NULL,
    fixed_cves        TEXT[] NOT NULL,
    severity_max      TEXT NOT NULL,
    emitter_status    TEXT NOT NULL,                -- 'sent' | 'failed' | 'rate-limited'
    emitter_response  TEXT,
    fired_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX rebuild_events_sub_at_idx ON rebuild_events (subscription_id, fired_at DESC);

-- Rate-limit ledger
CREATE TABLE rebuild_rate (
    subscription_id UUID NOT NULL,
    downstream_ref  TEXT NOT NULL,
    bucket_day      DATE NOT NULL,
    fired           INT NOT NULL DEFAULT 1,
    PRIMARY KEY (subscription_id, downstream_ref, bucket_day)
);
```

## f. Failure modes

- **Parent detection wrong.** If we infer `python:3.12-slim` but
  the user actually based on `python:3.12-bookworm`, we misfire.
  Mitigation: prefer `org.opencontainers.image.base.name` label
  (set by Buildkit / docker buildx) over history inference;
  store a `confidence` column and emit only at `confidence in
  ('label', 'history')` by default. `inferred` requires opt-in.
- **Emitter fails (CI down).** Event row marked `failed`; retried
  with exponential backoff up to 6h. After that, surfaces to the
  dashboard as a stale subscription.
- **Storm on a popular base** (`alpine:3.18` patched). Rate-limit
  table caps to 1/day per downstream. If subscription scope is too
  broad, operator narrows `descendants:` glob.
- **CI rebuild produces an image with WORSE CVEs.** Out of scope —
  the rebuild loop is just a trigger. The pushed result goes
  through 002 admission gate; if it's worse than the previous
  build, admission blocks and 014 surfaces the regression.
- **Subscription token leaked.** Rotation flow: update Secret →
  controller picks up → next emit uses new token. Revocation:
  delete the subscription.

## g. Migration story

`[rebuild] enabled = false`. Schema ships, lineage capture is a
no-op. Operators enable per-tenant; first run backfills lineage
for existing scans (incremental, restartable). No automatic
emission until at least one `RebuildSubscription` exists.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Lineage detection  | `crates/nebula-scanner/tests/lineage.rs`               | Both label + history paths                  |
| Subscription match | `crates/nebula-scanner/tests/sub_match.rs`             | Glob descendants matcher                    |
| GitHub emitter     | `crates/nebula-scanner/tests/emit_github.rs`           | Mock GH API                                 |
| GitLab emitter     | `crates/nebula-scanner/tests/emit_gitlab.rs`           | Mock GitLab API                             |
| Webhook HMAC       | `crates/nebula-scanner/tests/emit_webhook.rs`          | HMAC signing & client-side verify           |
| Rate limit         | `crates/nebula-scanner/tests/rate_limit.rs`            | 10 fires → 1 actually emits                 |
| End-to-end         | `tests/e2e/auto_rebuild_e2e.sh`                        | Patch base → assert downstream rebuild fired |

## i. Implementation slice count

3 slices, ~3 weeks:

1. Lineage capture (label parse + history inference) + `image_lineage`
   schema + lineage endpoint. Read-only feature: detect, don't fire.
2. `RebuildSubscription` CRD + reconciler + GitHub Dispatch emitter +
   rate limit + manual `_rebuild/trigger` endpoint.
3. GitLab + Tekton + generic-webhook emitters; CLI/MCP; e2e; docs
   (recipes per CI).
