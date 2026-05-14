# 011 — P2P Pull Acceleration (Spegel-style In-Cluster Peer Cache)

> **Summary.** Run a sidecar/DaemonSet on every Kubernetes node that
> advertises locally-cached blobs to peers via a libp2p gossip mesh
> and serves them from the node-local containerd content store. The
> registry stays the source of truth; the mesh just short-circuits
> repeated pulls of the same digest across pods on the same cluster.
> Cluster rollouts of a 1 GB image stop hammering the registry's
> egress: the first node pulls, the next 99 fetch from peers in
> parallel.

## a. Problem statement

When a Kubernetes cluster scales an image-heavy Deployment from 1 to
100 pods, the registry sees 99 redundant pulls of the same layers.
Even with HPA + storage CDN, registry egress and pod-start latency
both suffer. Spegel (Xenit) and Kraken (Uber) solved this for
plain-Distribution registries; ACR has "ACR-on-Arc" and "ACR
Connected Registry" as managed equivalents. Nexus has nothing in
this space. Shipping a P2P pull mesh as a first-class NebulaCR
feature gives cluster operators rollout speeds the closed-source
registries cannot match without paid tiers.

## b. Proposed approach

New crate `nebula-peer` shipped as a separate binary
`nebula-peer` (NOT linked into the registry). Architecture:

```
                    +-----------------------------+
                    |  NebulaCR registry (origin) |
                    +--------------+--------------+
                                   |
                +------------------+------------------+
                |                                     |
        +-------+-------+                     +-------+-------+
        |   Node A      |  libp2p gossip      |   Node B      |
        |  nebula-peer  |<------------------> |  nebula-peer  |
        |   sidecar     |                     |   sidecar     |
        +-------+-------+                     +-------+-------+
                | local blob store                    | local blob store
                v                                     v
         containerd CRI                        containerd CRI
```

Each `nebula-peer` instance:

1. **Registers as a containerd mirror** for the registry's hostname
   via `/etc/containerd/certs.d/<registry>/hosts.toml`. Pulls from
   pods on this node are routed to `localhost:5001/v2/...` first.
2. **Serves the OCI Distribution v2 read API** (manifest + blob) on
   `localhost:5001`. On a hit it streams from local containerd
   content store; on a miss it asks peers, falling back to the origin.
3. **Joins a libp2p gossip mesh** — peers announce digests they
   currently hold under topic `nebulacr/<cluster-id>/digests`. A
   bloom filter is published every 30 s; full digest-list on demand.
4. **Authenticates against the registry** with the same OIDC token
   the pod uses (IRSA / WI). On miss-and-fetch, the peer reuses the
   client's bearer token to pull from origin — peer never holds a
   long-lived registry credential.
5. **Verifies content addressability**. Every blob bytes is sha256'd
   on the way in; mismatch is logged + propagated as a peer-poison
   warning + skipped. Manifests are similarly verified. Signature
   verification (001) is delegated to containerd / kubelet — the peer
   never makes admission decisions.

Public trait so the mesh layer is swappable (libp2p today, gRPC
mesh tomorrow):

```rust
// crates/nebula-peer/src/mesh/mod.rs
#[async_trait]
pub trait PeerMesh: Send + Sync {
    async fn announce(&self, digests: &[Digest]) -> Result<(), MeshError>;
    async fn lookup(&self, digest: &Digest) -> Result<Vec<PeerEndpoint>, MeshError>;
    async fn fetch_from(&self, peer: PeerEndpoint, digest: &Digest)
        -> Result<BlobStream, MeshError>;
}
```

Default impl `Libp2pMesh` uses kad-dht + gossipsub from `rust-libp2p`.
Cluster discovery is a Kubernetes service (`headless`), with peer ID
derived from the node's serviceAccount-issued OIDC token (so
membership is bounded by the cluster's token issuer).

CLI (operator-side, talks to local peer):
`nebula-peer status` (mesh size, hit ratio, bytes saved),
`nebula-peer drop <digest>` (evict from local cache),
`nebula-peer pin <ref>` (pre-pull on this node).
The main `nebulacr` CLI gains `nebulacr peer install` (renders the
DaemonSet manifest for the active context).

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: PeerMesh
metadata:
  name: cluster-prod
spec:
  registryRef:
    host: registry.example.com
  cacheBytes: 21474836480           # 20 GiB on each node
  cacheEvictPolicy: lru             # lru | lfu | ttl
  cacheTtlHours: 168                # for ttl policy
  upstreamConcurrency: 4            # max parallel fetches from origin per node
  meshTransport:
    type: libp2p                    # libp2p | grpc (future)
    bootstrapServiceName: nebula-peer-headless
  prefetch:
    enabled: true
    triggerOnAdmission: true        # push admission-cleared digests to mesh
    repos: ["acme/prod/*"]
```

`PeerMesh` is cluster-scoped — one per cluster. The registry knows
which clusters speak to it via the `registryRef.host` field, which
the controller writes back to the registry's `peer_meshes` table so
the registry can target prefetch hints (see `prefetch` block).

## d. New HTTP routes

Peer-side (served by `nebula-peer`):

| Method | Path                                      | Auth scope         | Notes                                            |
| ------ | ----------------------------------------- | ------------------ | ------------------------------------------------ |
| GET    | `/v2/<name>/manifests/<ref>`              | `repo:pull`        | Mirrors origin; bearer reused                    |
| GET    | `/v2/<name>/blobs/<digest>`               | `repo:pull`        | Range-aware                                      |
| GET    | `/peer/health`                            | none               | Readiness for kubelet                            |
| GET    | `/peer/status`                            | `node:admin`       | Mesh stats                                        |
| POST   | `/peer/pin`                               | `node:admin`       | Body `{ref}` → pre-pull                          |
| DELETE | `/peer/blobs/{digest}`                    | `node:admin`       | Drop from cache                                  |

Registry-side additions:

| Method | Path                                      | Auth scope         | Notes                                            |
| ------ | ----------------------------------------- | ------------------ | ------------------------------------------------ |
| POST   | `/v2/_peer/prefetch`                      | `tenant:admin`     | Body `{cluster, ref}` → broadcasts hint to mesh   |
| GET    | `/v2/_peer/clusters`                      | `tenant:admin`     | Registered meshes + health                       |
| POST   | `/v2/_peer/register`                      | `node:admin`       | Peer announces itself; returns mesh secret       |

## e. Storage / Postgres schema

```sql
-- 0011_peer_mesh.sql
CREATE TABLE peer_meshes (
    id                UUID PRIMARY KEY,
    cluster_name      TEXT NOT NULL UNIQUE,
    bootstrap_url     TEXT NOT NULL,
    last_heartbeat    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    peer_count        INT NOT NULL DEFAULT 0,
    config_yaml       TEXT NOT NULL
);

CREATE TABLE peer_nodes (
    id               UUID PRIMARY KEY,
    mesh_id          UUID NOT NULL REFERENCES peer_meshes(id) ON DELETE CASCADE,
    node_name        TEXT NOT NULL,
    libp2p_id        TEXT NOT NULL,
    addr             INET,
    cache_bytes_used BIGINT NOT NULL DEFAULT 0,
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (mesh_id, node_name)
);
CREATE INDEX peer_nodes_seen_idx ON peer_nodes (last_seen DESC);

-- Aggregate stats: one row per cluster per hour. Cardinality bounded.
CREATE TABLE peer_stats_hourly (
    mesh_id          UUID NOT NULL REFERENCES peer_meshes(id),
    bucket_at        TIMESTAMPTZ NOT NULL,
    bytes_origin     BIGINT NOT NULL DEFAULT 0,
    bytes_peer       BIGINT NOT NULL DEFAULT 0,
    bytes_local      BIGINT NOT NULL DEFAULT 0,
    pulls            BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (mesh_id, bucket_at)
);
```

The peer caches themselves are NOT stored in Postgres — that is the
node-local containerd content store. Postgres holds only mesh
membership and rollup stats.

## f. Failure modes

- **Mesh partition.** Each side keeps serving from its local cache;
  on miss it falls back to origin. Spegel-style behaviour.
- **Peer poisons the mesh** with a wrong-digest blob. Content
  addressability protects us — the receiving peer detects the hash
  mismatch and drops the response. After N strikes the offending peer
  ID is locally blacklisted for an hour. (This is sufficient because
  digest collisions are pre-image attacks on sha256.)
- **Stolen bearer token replay.** Tokens are pod-scoped + short-lived
  (already true for OIDC); the peer never accepts a registry token
  on the mesh transport, only on the HTTP API.
- **Cache thrash on tiny nodes.** LRU eviction; `cache_bytes_used`
  metric exposed; alert at >90 % full so operators can size up.
- **Nebula-peer pod crash.** Containerd falls through to the origin
  via the `hosts.toml` fallback. Pulls are slower but unaffected.
- **Origin admission gate (002) blocks an image.** The peer respects
  the same admission decision via cached verdicts (Redis admission
  cache in 002 is shared with the peer's miss path). A blocked image
  cannot bypass admission via the mesh.

## g. Migration story

Peer mesh is opt-in per cluster. `[peer_mesh] enabled = false` on the
registry side ships a no-op control plane; the daemonset binary is a
separate artifact (`bwalia/nebula-peer:<version>`) and is not
deployed by default.

Operators install via:

```bash
nebulacr peer install --cluster prod \
  --registry registry.example.com \
  --cache-bytes 20Gi
```

This renders the DaemonSet + ConfigMap + RBAC manifests; operators
review and apply. Existing clusters need a one-time containerd
config patch (`hosts.toml`); the install command emits it.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Mesh announce/lookup | `crates/nebula-peer/tests/mesh_libp2p.rs`            | 5-node in-process mesh                      |
| Hash verify         | `crates/nebula-peer/tests/poison_resist.rs`           | Inject corrupt blob; assert mismatch dropped |
| Containerd integration | `tests/e2e/p2p_kind.sh`                            | kind cluster, 5 nodes, image rollout test    |
| Bearer reuse        | `crates/nebula-peer/tests/bearer_passthrough.rs`      | Short-lived JWT; peer reuses on miss        |
| Stats rollup        | `crates/nebula-registry/tests/peer_stats.rs`          | Hourly aggregation correctness               |

External CI dep: `kind` cluster harness + `containerd` 1.7+ with the
mirror config feature. Already used by other registry e2e tests.

## i. Implementation slice count

5 slices, ~5 weeks (largest of the bunch — mesh code is non-trivial):

1. `nebula-peer` crate scaffold + OCI v2 read-only HTTP server +
   containerd content-store reader. Single-node only — no mesh yet.
2. `PeerMesh` trait + `Libp2pMesh` impl + announce/lookup/fetch.
3. Registry-side `PeerMesh` CRD + reconciler + `_peer/register`,
   `_peer/clusters`, `_peer/prefetch` routes.
4. Stats rollup + Helm DaemonSet template + `nebulacr peer install`.
5. e2e on kind, hardening (bearer passthrough, poison resistance,
   cache eviction), docs.
