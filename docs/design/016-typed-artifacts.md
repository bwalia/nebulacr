# 016 — Typed-Artifact Registries (Helm / WASM / AI Models / Terraform)

> **Summary.** Promote the OCI-artifact path from "everything is an
> opaque blob" to a typed registry where each well-known media type
> gets schema validation, a tailored UI viewer, and per-type
> retention. Targets the four formats teams most often complain
> about pushing to a "Docker registry": Helm charts, WebAssembly
> components, AI/ML models (Hugging Face / GGUF), and Terraform
> modules. All flow through the existing OCI 1.1 `application/vnd.*`
> manifest path; the validation and rendering are additive.

## a. Problem statement

Every ecosystem has settled on OCI as the universal artifact
distribution format, but registries treat the new formats as
"docker push but invisible." Teams cannot answer:
"which Helm chart version is in our registry, what values does it
expose, is its `image:` reference signed, and is the `appVersion`
the same one our deployments are using?" — without a separate
chart museum, a separate WASM tool, and a separate ML registry.
ACR has typed-artifact support behind paid tiers (Helm, OCI WASM
in preview); Nexus has separate format types (a major source of
its operational complexity and licensing cost). NebulaCR can do all
this in one OCI registry by reading the media type and dispatching
to a per-type validator + viewer.

## b. Proposed approach

New crate `nebula-artifact-types`. Single registry of validators:

```rust
// crates/nebula-artifact-types/src/lib.rs
#[async_trait]
pub trait ArtifactType: Send + Sync {
    fn type_id(&self) -> &'static str;            // "helm" | "wasm" | "model" | "tfmodule"
    fn matches(&self, mt: &MediaType) -> bool;

    /// Run on PUT manifest after blob upload. Returns parsed metadata.
    async fn validate(&self, manifest: &Manifest, fetch: &dyn BlobFetcher)
        -> Result<ArtifactMetadata, ArtifactError>;

    /// Render structured view for the dashboard.
    fn render(&self, meta: &ArtifactMetadata) -> ViewModel;
}

pub struct HelmType;            // OCI helm-chart media types
pub struct WasmType;            // application/vnd.wasm.config.v0+json
pub struct ModelType;           // application/vnd.cncf.model.config.v1+json (CNCF model spec)
pub struct TerraformModuleType; // application/vnd.opentofu.modulepkg
```

Wiring point: `put_manifest` at
`crates/nebula-registry/src/main.rs:886`. After the manifest is
written, a registry of `ArtifactType` impls is consulted; the first
that matches runs `validate`. On error, the manifest is rejected
(opt-in per project). On success, parsed metadata is stored in
`artifact_meta` and surfaced via the dashboard + a typed JSON
endpoint.

### Helm

- Validates the chart `Chart.yaml` blob exists and `name` /
  `version` match the OCI tag.
- Extracts `appVersion`, `dependencies`, `kubeVersion`, declared
  `values.yaml` schema if any.
- Cross-references `image:` references in templates to other tags
  in this registry (warn if missing or unsigned, when 001 enabled).
- Provides `helm pull` over OCI compat — already free with OCI
  manifests; we just add the dashboard.

### WASM

- Validates the magic header `\0asm` and version on the WASM blob.
- Extracts module imports/exports + interface types.
- For OCI Component Model artifacts, parses the WIT world.
- Future: optional `wasm-validate` / `wasm-tools` shell-out behind
  feature flag.

### Model

- Conforms to CNCF model spec (`org.cnai.model.config.v1+json`).
- Records framework (PyTorch, TF, ONNX, GGUF), parameter count,
  quantization, source dataset hash if declared.
- License classification reuses 014's licence detector on the
  `LICENSE` file inside the artifact.

### Terraform

- Walks `.tf` / `.tofu` files for declared providers + modules.
- Parses `versions.tf` for required-providers constraints.
- Optional registry-style index page with input variable docs.

Per-type retention: Helm keeps last 5 minor versions per major;
WASM keeps last 10 versions; models keep last 3 (storage cost).
Configurable; see CRD.

CLI: `nebulacr helm push|pull|list|inspect`,
`nebulacr wasm inspect`, `nebulacr model inspect`,
`nebulacr terraform inspect`. Each is a thin wrapper around the
generic OCI plumbing + the typed metadata endpoint. MCP:
`list_typed_artifacts`, `inspect_artifact`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Project
spec:
  tenantRef: acme
  artifactTypes:
    helm:
      enabled: true
      validate: strict           # strict | lenient | off
      retention:
        keepMinorVersions: 5
    wasm:
      enabled: true
      validate: lenient
    model:
      enabled: true
      validate: strict
      maxBlobBytes: 53687091200  # 50 GiB single-blob ceiling for big models
    terraform:
      enabled: false
```

`validate: off` keeps OCI semantics (any media type accepted) — useful
for repos that mix multiple artifact types and don't want strict
type-policing.

## d. New HTTP routes

| Method | Path                                                       | Auth scope         | Notes                                            |
| ------ | ---------------------------------------------------------- | ------------------ | ------------------------------------------------ |
| GET    | `/v2/<name>/artifact-meta/<digest>`                        | `repo:pull`        | Returns `ArtifactMetadata` for a manifest        |
| GET    | `/v2/<name>/artifact-render/<digest>`                      | `repo:pull`        | Pre-rendered view JSON for the dashboard         |
| GET    | `/v2/_artifact-types`                                      | `tenant:read`      | List supported types + status                    |
| GET    | `/v2/_artifact-types/{id}/index?project=...`               | `tenant:read`      | Type-specific catalog (e.g. Helm chart index)    |

The standard OCI manifest / blob endpoints remain unchanged; clients
keep using `helm push oci://...`, `oras push`, etc.

## e. Storage / Postgres schema

```sql
-- 0016_artifact_types.sql
CREATE TABLE artifact_meta (
    digest          TEXT PRIMARY KEY,                -- manifest digest
    type_id         TEXT NOT NULL,                   -- 'helm' | 'wasm' | 'model' | 'tfmodule'
    metadata        JSONB NOT NULL,                  -- type-specific shape
    media_type      TEXT NOT NULL,
    bytes           BIGINT NOT NULL,
    validated       BOOLEAN NOT NULL,
    validation_msg  TEXT,
    parsed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX artifact_meta_type_idx ON artifact_meta (type_id);
CREATE INDEX artifact_meta_meta_idx ON artifact_meta USING GIN (metadata jsonb_path_ops);

-- Per-type catalog for UI-level browse. Materialised view refreshed
-- by the controller on push.
CREATE TABLE artifact_index (
    type_id         TEXT NOT NULL,
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    name            TEXT NOT NULL,                   -- chart name / module name / model name
    versions        JSONB NOT NULL,                  -- [{tag, digest, semver, appVersion}]
    PRIMARY KEY (type_id, tenant, project, name)
);
```

Heavy artifacts (Helm tarball, WASM bytes, model weights) stay in
content-addressed blob storage. Postgres holds only parsed metadata
and the index.

## f. Failure modes

- **Validator panics on a malformed blob.** Wrap in
  `tokio::task::spawn_blocking` + `catch_unwind`; manifest accepted
  with `validated: false, validation_msg: "panic"`. Operators can
  set `validate: strict` to reject instead.
- **Helm chart's `image:` references unsigned image when 001
  required.** Validator emits a `warn` finding (014 surface); does
  not reject the chart. Admission policy at 002 can elevate to
  `block`.
- **Model blob exceeds `maxBlobBytes`.** Push rejected at blob
  upload time; existing OCI distribution semantics.
- **`validate: strict` rejects a perfectly-good niche format the
  validator doesn't know about.** Operator drops to `lenient` or
  `off`. Validators are advisory; the registry never depends on
  them for correctness of OCI semantics.
- **WIT-world parser is heavy on memory.** Per-validator timeout
  (default 30 s) + size cap (default 50 MiB blob); over-budget →
  `validated: false, msg: "validator timeout"`.

## g. Migration story

`[artifact_types] enabled = false`. Existing pushes still work
unchanged. Operators enable types per project; backfill can re-walk
existing manifests of matching media types via a one-shot
`nebulacr artifact reindex --project ...` job (uses the existing
controller worker pool).

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Helm validate      | `crates/nebula-artifact-types/tests/helm.rs`           | bitnami chart fixtures                      |
| WASM validate      | `crates/nebula-artifact-types/tests/wasm.rs`           | Component Model + plain WASM module         |
| Model validate     | `crates/nebula-artifact-types/tests/model.rs`          | CNCF model spec sample artifacts            |
| TF module validate | `crates/nebula-artifact-types/tests/tfmodule.rs`       | OpenTofu module fixtures                    |
| Index materialise  | `crates/nebula-artifact-types/tests/index.rs`          | Push → index refresh assertions             |
| End-to-end Helm    | `tests/e2e/helm_push_pull.sh`                          | `helm push oci://...` → list → install      |
| Strict reject      | `crates/nebula-artifact-types/tests/strict_reject.rs`  | Malformed Helm chart blocked under strict   |

## i. Implementation slice count

4 slices, ~4 weeks:

1. `nebula-artifact-types` scaffold + `ArtifactType` trait + Helm
   impl + `artifact_meta` schema + `put_manifest` integration.
2. WASM type + per-project validation modes + artifact-meta endpoint.
3. Model type + Terraform module type + artifact-index + reindex
   command.
4. Per-type retention integration with 004/009 GC, dashboard
   viewers (delegated to 007's UI), CLI/MCP, docs.
