# 012 — Migration Importer (Nexus / Harbor / ACR / Distribution)

> **Summary.** A streaming importer that mirrors a source registry's
> repositories, tags, manifests, blobs, retention rules, and
> permissions into NebulaCR with content-addressable dedup, restartable
> jobs, and a per-source adapter trait. One command (`nebulacr
> import nexus://… → tenant/project/`) gets a Nexus-locked team off
> their stagnant registry without rebuilding images.

## a. Problem statement

The single largest reason teams stay on Sonatype Nexus despite hating
it is switching cost: thousands of tags, retention policies, robot
accounts, and CI references all break the day they cut over. ACR
offers `acr import` for cross-registry copy but only between ACRs.
Harbor offers replication which is tag-by-tag and stops on first
failure. Nothing in OSS ships a "give me your old registry, I'll
take it from here" path. NebulaCR has the unfair advantage of being
a fresh registry where every blob is content-addressed in our
storage anyway — the importer just has to translate metadata.

## b. Proposed approach

New crate `nebula-import`. One trait, one importer per source:

```rust
// crates/nebula-import/src/source.rs
#[async_trait]
pub trait RegistrySource: Send + Sync {
    fn id(&self) -> &'static str;                  // "nexus" | "harbor" | "acr" | "distribution"

    async fn list_repositories(&self) -> BoxStream<'_, Repository>;
    async fn list_tags(&self, repo: &Repository) -> BoxStream<'_, Tag>;
    async fn fetch_manifest(&self, repo: &Repository, tag: &Tag)
        -> Result<(Bytes, MediaType), ImportError>;
    async fn fetch_blob(&self, repo: &Repository, digest: &Digest)
        -> Result<BlobStream, ImportError>;

    /// Source-specific metadata that doesn't fit the OCI shape.
    async fn list_retention_rules(&self, repo: &Repository)
        -> Result<Vec<RetentionRuleRaw>, ImportError>;
    async fn list_permissions(&self, repo: &Repository)
        -> Result<Vec<PermissionRaw>, ImportError>;
}

pub struct NexusSource { client: NexusClient, /* ... */ }
pub struct HarborSource { client: HarborClient, /* ... */ }
pub struct AcrSource { client: AcrClient, /* ... */ }
pub struct DistributionSource { client: DistributionClient, /* ... */ }
```

The importer runner:

```rust
// crates/nebula-import/src/runner.rs
pub struct ImportRunner {
    src: Arc<dyn RegistrySource>,
    dst: NebulaCrClient,
    db: PgPool,
    parallel: usize,            // default 8
}

impl ImportRunner {
    /// Restartable. Reads progress from import_jobs + import_repos
    /// + import_blobs and resumes where it left off.
    pub async fn run(self, job_id: Uuid) -> Result<ImportReport, ImportError>;
}
```

Pipeline (per repository, parallelised):

1. Compare manifest list; for each tag missing in dest:
2. Fetch manifest from source; rewrite media types where needed
   (Nexus + ACR can both emit Docker v2.2 — accepted as-is).
3. For each blob descriptor in the manifest, check
   `HEAD /v2/<dst>/blobs/<digest>` first. If present (already
   imported via another tag), skip the blob fetch entirely. If
   absent, stream from source → registry's `chunked upload` API.
4. After all blobs land, `PUT /v2/<dst>/manifests/<tag>`.
5. Translate retention rules + permissions via the source's
   adapter, write to NebulaCR's `RetentionPolicy` + `AccessPolicy`
   CRDs (no overwrite — the runner emits a YAML diff and asks
   for confirmation unless `--accept-policies` is passed).

Why not skopeo: skopeo handles step 1-4 well, but it can't
restart against state, can't translate retention rules, has no
notion of NebulaCR tenants. The runner shells skopeo behaviour
into Rust and adds the bookkeeping NebulaCR needs.

Path translation:

```bash
# Nexus repo "docker-prod-hosted/myorg/api"
#   → tenant=acme, project=prod, repo=myorg/api, tag=*
nebulacr import \
  nexus://nexus.example.com/docker-prod-hosted \
  --to acme/prod/ \
  --include 'myorg/*' \
  --exclude '*-test' \
  --since 30d \
  --accept-policies

# ACR repo "myacr.azurecr.io/team/svc"
#   → tenant=acme, project=prod, repo=team/svc, tag=*
nebulacr import \
  acr://myacr.azurecr.io \
  --to acme/prod/ \
  --auth azure-cli
```

`--dry-run` reports what would be copied; `--resume <job-id>`
restarts.

CLI: `nebulacr import …`, `nebulacr import status <job-id>`,
`nebulacr import abort <job-id>`. MCP: `start_import`,
`get_import_status`, `abort_import`, `list_import_sources`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: ImportJob
metadata:
  name: nexus-cutover
  namespace: tenant-acme
spec:
  source:
    type: nexus              # nexus | harbor | acr | distribution
    url: https://nexus.example.com
    repository: docker-prod-hosted
    credentialsRef:
      name: nexus-readonly
  target:
    tenant: acme
    project: prod
  filter:
    include: ["myorg/*"]
    exclude: ["*-test"]
    since: 30d              # only tags newer than this
  parallelism: 8
  policyTranslation: accept # accept | review | skip
  schedule: ""              # one-shot if empty; cron for ongoing mirror
status:
  phase: running            # queued | running | succeeded | failed
  reposCopied: 47
  reposTotal: 312
  tagsCopied: 1842
  tagsTotal: 11403
  bytesCopied: 213847510144
  startedAt: 2026-05-12T03:00:00Z
  lastActivityAt: 2026-05-12T03:42:11Z
  resumeCursor: "myorg/svc-X@v1.4.2"
```

`schedule: "@hourly"` makes the importer run as a long-lived mirror
— useful during a multi-week cutover where teams still push to the
old registry while transitioning. Hash-only re-checks short-circuit
already-copied tags.

## d. New HTTP routes

| Method | Path                                                       | Auth scope         | Notes                                            |
| ------ | ---------------------------------------------------------- | ------------------ | ------------------------------------------------ |
| POST   | `/v2/_import/jobs`                                         | `tenant:admin`     | Body = ImportJob spec; returns job id            |
| GET    | `/v2/_import/jobs/{id}`                                    | `tenant:admin`     | Status + cursor                                  |
| POST   | `/v2/_import/jobs/{id}/abort`                              | `tenant:admin`     | Cancel in-flight                                 |
| POST   | `/v2/_import/jobs/{id}/resume`                             | `tenant:admin`     | Resume from cursor                               |
| GET    | `/v2/_import/sources`                                      | `tenant:read`      | List supported source adapters + features        |
| POST   | `/v2/_import/dry-run`                                      | `tenant:admin`     | Returns count + bytes estimate; doesn't write    |

## e. Storage / Postgres schema

```sql
-- 0012_import.sql
CREATE TABLE import_jobs (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    spec            JSONB NOT NULL,
    phase           TEXT NOT NULL,                    -- queued | running | succeeded | failed | aborted
    repos_total     INT NOT NULL DEFAULT 0,
    repos_copied    INT NOT NULL DEFAULT 0,
    tags_total      INT NOT NULL DEFAULT 0,
    tags_copied     INT NOT NULL DEFAULT 0,
    bytes_copied    BIGINT NOT NULL DEFAULT 0,
    resume_cursor   TEXT,
    started_at      TIMESTAMPTZ,
    last_activity   TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    error           TEXT
);
CREATE INDEX import_jobs_phase_idx ON import_jobs (phase, started_at DESC);

-- Per-tag idempotency: source-side digest → NebulaCR digest.
-- Avoids re-fetching when a tag is moved to an already-known digest.
CREATE TABLE import_tag_state (
    job_id          UUID NOT NULL REFERENCES import_jobs(id) ON DELETE CASCADE,
    src_repo        TEXT NOT NULL,
    src_tag         TEXT NOT NULL,
    src_digest      TEXT NOT NULL,
    dst_digest      TEXT,                              -- NULL until manifest pushed
    bytes           BIGINT,
    state           TEXT NOT NULL,                     -- pending | copying | done | failed
    error           TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, src_repo, src_tag)
);
CREATE INDEX import_tag_state_pending_idx
    ON import_tag_state (job_id, state) WHERE state IN ('pending','copying');

-- Per-blob dedup. Records that the importer already verified blob
-- exists in destination so a re-run skips the HEAD probe.
CREATE TABLE import_blob_seen (
    job_id          UUID NOT NULL,
    digest          TEXT NOT NULL,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, digest)
);
```

## f. Failure modes

- **Source 401 mid-run.** Worker pauses, refreshes the credential
  via `credentialsRef`, retries up to 5 times with exp backoff.
- **Source 5xx on a single tag.** Tag marked `failed` in
  `import_tag_state`, runner continues. End-of-run report lists
  failures; `--resume` retries only failed rows.
- **Destination upload fails midway through a 4 GiB blob.** Chunked
  uploads have idempotent finalize: the runner records the upload
  session id and resumes. Storage backend (S3) handles partial
  upload cleanup via lifecycle rule.
- **Source has manifest list / OCI Index variants we can't represent.**
  Currently we copy as-is — NebulaCR already supports image indexes.
  If a source emits a vendor-specific manifest type (e.g. ACR helm
  v3 OCI), we copy bytes verbatim; clients that pull need to
  understand it.
- **Permission translation lossy.** Nexus has fine-grained access
  rules NebulaCR's RBAC doesn't model 1:1. Runner emits a YAML
  delta and refuses to apply unless `--accept-policies` is set.
- **Long-running mirror diverges from source.** Schedule runs detect
  deletions in source (manifest GET → 404). By default the importer
  is **additive** — it never deletes from NebulaCR. `--mirror-deletes`
  flag is opt-in and hard-gated behind a confirmation prompt.

## g. Migration story

`[import] enabled = false` ships the schema only; the controller
ignores `ImportJob` CRDs. Operators enable per-tenant. Adapters
ship feature-flagged so an operator can enable just `nexus` without
pulling in the Azure SDK.

Adapters are independently versioned: adding `gitlab` or `quay`
later is a new module, not a schema change.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Nexus adapter      | `crates/nebula-import/tests/nexus_adapter.rs`          | Recorded fixtures; full repo walk           |
| Harbor adapter     | `crates/nebula-import/tests/harbor_adapter.rs`         | Recorded fixtures                           |
| ACR adapter        | `crates/nebula-import/tests/acr_adapter.rs`            | Recorded fixtures + Azure SDK mock          |
| Resume cursor      | `crates/nebula-import/tests/resume.rs`                 | Postgres testcontainer; kill mid-run        |
| Blob dedup         | `crates/nebula-import/tests/blob_dedup.rs`             | Same digest in 2 tags; only 1 fetch         |
| Policy translation | `crates/nebula-import/tests/policy_translate.rs`       | Round-trip Nexus rule → AccessPolicy YAML   |
| End-to-end         | `tests/e2e/import_nexus_e2e.sh`                        | Bring up Nexus container + run real import  |

External test deps: `sonatype/nexus3`, `goharbor/harbor` containers
in CI for end-to-end. Recorded JSON fixtures keep unit tests fast.

## i. Implementation slice count

5 slices, ~5 weeks (each adapter is non-trivial):

1. `nebula-import` crate scaffold + `RegistrySource` trait +
   `DistributionSource` (the simplest — vanilla Distribution v2 API)
   + runner + schema.
2. Nexus adapter (handles `docker-hosted`, `docker-group`,
   `docker-proxy` repo types).
3. Harbor adapter (project / repository hierarchy translation +
   robot account mapping).
4. ACR adapter (Azure SDK auth, ACR's task / RBAC quirks).
5. Policy translation framework, scheduled mirror mode, CLI/MCP,
   docs (per-source migration runbooks).
