# 010 — Lazy Image Pulling (eStargz / zstd-chunked / SOCI)

> **Summary.** Serve range-addressable layers with a pre-indexed
> table-of-contents so containerd-snapshotter / nydus / SOCI can fetch
> only the files actually `read(2)`-ed at container start. Add a
> background "TOC indexer" that runs after every push and writes the
> TOC artifact as a referrer to the manifest (OCI 1.1 referrers API).
> Cold-start times for large images drop from minutes to seconds; the
> existing blob storage layout is unchanged.

## a. Problem statement

A 1.2 GB Python ML image takes 90+ seconds to pull and another 30+
seconds to extract before the container can start. Most of those
bytes are never read at runtime. eStargz (Google), zstd:chunked
(Red Hat / containers/storage), and SOCI (AWS) all solve this by
making the image format range-addressable, then mounting the layer
on-demand. None of ACR, Nexus, Harbor, or Distribution-3 ship the
indexer — operators have to run `ctr-remote image optimize` out of
band, then upload the converted image as a separate tag. NebulaCR
shipping this in-registry is a real differentiator: every pushed
image becomes lazy-pullable automatically.

## b. Proposed approach

New crate `nebula-lazy` with a single trait and three implementations:

```rust
// crates/nebula-lazy/src/lib.rs
#[async_trait]
pub trait TocIndexer: Send + Sync {
    fn media_type(&self) -> &'static str;
    fn supports(&self, layer: &Descriptor) -> bool;

    /// Streams the source layer, produces the TOC + (optionally) a
    /// rewritten layer blob. Returns descriptors for storage.
    async fn index(&self, src: BlobReader<'_>)
        -> Result<TocOutput, LazyError>;
}

pub struct TocOutput {
    pub toc_blob: Bytes,                  // CycloneDX-shaped manifest of files
    pub toc_descriptor: Descriptor,
    pub indexed_layer: Option<(Bytes, Descriptor)>, // None for SOCI passthrough
}

pub struct EstargzIndexer { /* ... */ }
pub struct ZstdChunkedIndexer { /* ... */ }
pub struct SociIndexer { /* references existing layer; just builds TOC */ }
```

Pipeline:

1. After `complete_blob_upload` accepts a layer
   (`crates/nebula-registry/src/main.rs:1458`), if the layer's media
   type is `application/vnd.oci.image.layer.v1.tar+gzip` (or zstd),
   enqueue a `LazyIndexJob{layer_digest, target_format}` to a new
   `nebula_lazy::Queue` (Postgres-backed, identical pattern to the
   scanner queue).
2. Worker pulls the layer once, runs all enabled indexers in
   parallel, writes:
   - **eStargz**: the rewritten layer (also a valid gzip tarball — old
     clients still pull it as the layer) + the TOC artifact.
   - **zstd:chunked**: rewritten zstd layer with an internal index
     embedded in the trailer + a TOC artifact.
   - **SOCI**: the original layer is unchanged; the TOC artifact (an
     OCI artifact with `mediaType:
     application/vnd.amazon.soci.index.v1+json`) is uploaded.
3. The TOC is registered as a *referrer* of the manifest under OCI 1.1
   referrers (`/v2/<repo>/referrers/<manifest-digest>`). Lazy-aware
   clients discover it; non-aware clients see nothing different.
4. For eStargz / zstd:chunked, the registry advertises a second tag
   `<tag>-esgz` / `<tag>-zstdchunked` so users can opt into the
   converted layer explicitly. The original tag is untouched.

Range serving: the existing `GET /v2/<repo>/blobs/<digest>` already
supports `Range:` headers via `axum`. The new piece is the
`Accept-Encoding: zstd-chunked, estargz` content negotiation: when a
lazy-aware client asks for the layer, the registry returns the
indexed variant if available; otherwise it returns the original.

`pull_through_cache`: when proxying upstream layers (Docker Hub, GHCR)
the indexer also runs over the cached copy, so pulls of
`registry.example.com/library/python:3.12` benefit lazily.

CLI: `nebulacr lazy index <ref> --format estargz|zstd-chunked|soci`
forces re-indexing; `nebulacr lazy status <digest>` shows TOC
availability. MCP: `lazy_status`, `lazy_reindex`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Project
metadata:
  name: prod
spec:
  tenantRef: acme
  lazyPull:
    enabled: true
    formats: [estargz, zstd-chunked, soci]    # subset, or [] to disable
    minLayerBytes: 10485760                    # 10 MiB — skip tiny layers
    rewriteOriginalTag: false                  # if true, replace layer
                                               # in-place (destructive)
```

`rewriteOriginalTag: false` (default) keeps the original layer; the
indexed variant is stored under a sibling digest. `true` is for cost-
sensitive operators willing to accept that pre-rewrite digests change
on the way out — typically only used in caching tiers.

## d. New HTTP routes

| Method | Path                                                    | Auth scope         | Notes                                            |
| ------ | ------------------------------------------------------- | ------------------ | ------------------------------------------------ |
| GET    | `/v2/<name>/referrers/<digest>`                         | `repo:pull`        | OCI 1.1 standard — returns TOC artifacts as referrers |
| GET    | `/v2/<name>/blobs/<digest>?fmt=estargz`                 | `repo:pull`        | Returns indexed variant, 404 if not yet indexed  |
| POST   | `/v2/_lazy/index`                                       | `repo:push`        | Body `{ref, format}` → enqueues indexing job     |
| GET    | `/v2/_lazy/jobs/{id}`                                   | `repo:pull`        | Job status                                        |
| GET    | `/v2/_lazy/stats?tenant=...`                            | `tenant:read`      | Coverage % per project, bytes saved              |

`Accept-Encoding`-based negotiation on the standard blob route is the
preferred client path; the `?fmt=` query string is the fallback for
tooling that can't set headers.

## e. Storage / Postgres schema

```sql
-- 0010_lazy_pull.sql
CREATE TABLE lazy_index (
    layer_digest    TEXT NOT NULL,             -- the source layer
    format          TEXT NOT NULL,             -- 'estargz' | 'zstd-chunked' | 'soci'
    indexed_digest  TEXT NOT NULL,             -- the indexed/rewritten blob (or = source for SOCI)
    toc_digest      TEXT NOT NULL,             -- the TOC artifact digest
    bytes_original  BIGINT NOT NULL,
    bytes_indexed   BIGINT NOT NULL,
    indexed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (layer_digest, format)
);
CREATE INDEX lazy_index_format_idx ON lazy_index (format, indexed_at DESC);

CREATE TABLE lazy_jobs (
    id              UUID PRIMARY KEY,
    layer_digest    TEXT NOT NULL,
    format          TEXT NOT NULL,
    status          TEXT NOT NULL,             -- 'queued' | 'running' | 'done' | 'failed'
    error           TEXT,
    enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ
);
CREATE INDEX lazy_jobs_status_idx ON lazy_jobs (status, enqueued_at);

-- Referrer rows for OCI 1.1. Avoids re-walking blobs at request time.
CREATE TABLE referrers (
    subject_digest  TEXT NOT NULL,             -- the manifest being referenced
    artifact_digest TEXT NOT NULL,
    artifact_type   TEXT NOT NULL,
    media_type      TEXT NOT NULL,
    size            BIGINT NOT NULL,
    PRIMARY KEY (subject_digest, artifact_digest)
);
CREATE INDEX referrers_subject_idx ON referrers (subject_digest);
```

`referrers` is shared with 001 (signature artifacts), 015 (provenance),
and 014 (extended scan results). The lazy indexer is one of several
producers.

## f. Failure modes

- **Indexer fails (corrupt tarball, OOM).** Job marked `failed`;
  retried with exponential backoff up to 3 attempts. Manifest is
  unaffected — clients pull the un-indexed layer.
- **Indexed variant disagrees with source on uncompressed digest.**
  Build-time integrity check: `tar -tvf` on the rewritten blob must
  list the same files with the same sizes. Mismatch → discard, alert.
- **Storage doubled.** Operators worried about storage cost set
  `rewriteOriginalTag: true` to drop the original after successful
  indexing. Default is to keep both for safety.
- **Pull-through cache layer is rewritten then upstream re-pushes
  the same digest.** OCI digests are content-addressed; if the bytes
  match, the indexed variant remains valid. If the bytes differ, the
  upstream digest changes and a new indexing job is enqueued.
- **Lazy-aware client requests `?fmt=estargz` before indexing
  finishes.** Returns 404 with `WWW-NebulaCR-Indexing: in-progress,
  poll /v2/_lazy/jobs/<id>`; client falls back to plain pull.

## g. Migration story

`[lazy_pull] enabled = false` ships a no-op. Existing pushes do not
spawn indexing jobs. Operators enable per-project; the indexer
backfills on first run (every layer in the project gets enqueued
once). Backfill cost is bounded — same code path as on-push indexing.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| eStargz round-trip | `crates/nebula-lazy/tests/estargz_roundtrip.rs`        | Build → index → mount via stargz-snapshotter container |
| zstd:chunked       | `crates/nebula-lazy/tests/zstd_chunked.rs`             | Trailer index validation                    |
| SOCI artifact      | `crates/nebula-lazy/tests/soci_artifact.rs`            | Validate JSON against AWS schema            |
| Referrers API      | `crates/nebula-registry/tests/referrers_api.rs`        | OCI conformance tests                       |
| Range fetch        | `crates/nebula-registry/tests/range_serve.rs`          | Concurrent partial range pulls              |
| End-to-end         | `tests/e2e/lazy_pull_e2e.sh`                           | Pull big image, measure time to /bin/sh prompt |

External test deps: `containerd-stargz-grpc` snapshotter container
for eStargz validation. Pinned to a known-good image in CI.

## i. Implementation slice count

4 slices, ~4 weeks:

1. `nebula-lazy` crate scaffold + `TocIndexer` trait +
   `EstargzIndexer` impl + schema. Indexer enqueued from
   `complete_blob_upload`, no client-facing changes yet.
2. Referrers API (`/v2/<name>/referrers/<digest>`) + `referrers`
   table + content-negotiation on `GET /v2/<name>/blobs/<digest>`.
3. `ZstdChunkedIndexer` + `SociIndexer`. Per-project config wiring +
   stats endpoint.
4. CLI/MCP, Helm flag, backfill driver, e2e harness, docs (containerd
   snapshotter setup guide).
