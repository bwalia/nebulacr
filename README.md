# NebulaCR

A cloud-native Docker/OCI container registry built in Rust with multi-tenancy, zero-trust authentication, and pull-through caching.

## Features

- **OCI Distribution API v2** compliant registry
- **Pull-through cache** for Docker Hub, GHCR, GCR, Quay.io, and registry.k8s.io
- **Multi-tenancy** with Tenant, Project, AccessPolicy, and TokenPolicy CRDs
- **Zero-trust auth** via OIDC (Google, GitHub Actions, GitLab CI, Azure AD)
- **Multiple storage backends** — filesystem, S3, GCS, Azure Blob
- **High availability** — stateless services, HPA, PDB, circuit breakers
- **Multi-region replication** with async/semi-sync modes
- **Observability** — Prometheus metrics, structured JSON logging, OpenTelemetry tracing
- **Rate limiting** per IP and per tenant
- **Webhook notifications** for registry events

## Architecture

```
                        +------------------+
                        |    Ingress /     |
                        |   LoadBalancer   |
                        +--------+---------+
                                 |
                    /v2          |         /auth
               +----+----+      |     +----+----+
               | Registry |      |     |  Auth   |
               | (:5000)  |------+-----| (:5001) |
               +----+----+            +----+----+
                    |                      |
            +-------+-------+              |
            |       |       |         OIDC Provider
         S3/GCS  Azure  Filesystem   (Google, GitHub, etc.)
```

**Two core services:**

| Service | Port | Metrics | Purpose |
|---------|------|---------|---------|
| `nebula-registry` | 5000 | 9090 | OCI Distribution API, blob/manifest storage, pull-through cache |
| `nebula-auth` | 5001 | 9091 | OIDC validation, JWT issuance, RBAC policy resolution |

## Quick Start

### Pull-Through Cache (Simplest Install)

Deploy NebulaCR as a caching proxy with zero configuration:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr --namespace nebulacr --create-namespace
```

That's it. NebulaCR caches images from Docker Hub, GHCR, GCR, Quay.io, and registry.k8s.io out of the box.

Pull images through the cache:

```bash
# Docker Hub (default upstream)
docker pull <nebulacr-host>:5000/library/nginx:latest

# GHCR
docker pull <nebulacr-host>:5000/ghcr.io/org/repo:tag

# Quay.io
docker pull <nebulacr-host>:5000/quay.io/prometheus/prometheus:latest
```

### Configure containerd to Use NebulaCR as a Mirror

Add to `/etc/containerd/config.toml` on each node (or use a DaemonSet):

```toml
[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["http://nebulacr-registry.nebulacr.svc.cluster.local:5000"]
```

### Local Development with Docker Compose

```bash
docker compose up -d
```

This starts the registry on `localhost:5000`, auth on `localhost:5001`, and auto-generates JWT signing keys.

```bash
# Push an image
docker tag myapp:latest localhost:5000/myorg/myapp:latest
docker push localhost:5000/myorg/myapp:latest

# Pull it back
docker pull localhost:5000/myorg/myapp:latest
```

## Installation

### Helm Chart

The chart is published to both GitHub Pages and GHCR OCI:

```bash
# Option A: OCI registry (recommended)
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace

# Option B: Helm repository
helm repo add nebulacr https://bwalia.github.io/nebulacr
helm repo update
helm install nebulacr nebulacr/nebulacr \
  --namespace nebulacr --create-namespace
```

See [deploy/helm/nebulacr/README.md](deploy/helm/nebulacr/README.md) for the full Helm chart reference.

### Production Install with OIDC and S3

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace \
  --set oidc.enabled=true \
  --set oidc.issuerUrl="https://accounts.google.com" \
  --set oidc.clientId="YOUR_CLIENT_ID" \
  --set oidc.clientSecret="YOUR_CLIENT_SECRET" \
  --set storage.backend=s3 \
  --set storage.s3.bucket=my-registry-bucket \
  --set storage.s3.region=us-east-1 \
  --set ingress.enabled=true \
  --set ingress.host=registry.example.com \
  --set ingress.tls.enabled=true
```

### Docker Hub Credentials (Avoid Rate Limits)

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace \
  --set pullThroughCache.upstreams.docker\\.io.username=myuser \
  --set pullThroughCache.upstreams.docker\\.io.password=mytoken
```

## Configuration Reference

See [`config/nebulacr.example.toml`](config/nebulacr.example.toml) for all available settings.

### Storage Backends

| Backend | Value | Key Settings |
|---------|-------|-------------|
| Local filesystem | `filesystem` | `rootDirectory`, PVC size |
| Amazon S3 / MinIO | `s3` | `bucket`, `region`, `endpoint`, `encrypt` |
| Google Cloud Storage | `gcs` | `bucket`, `keyfile` |
| Azure Blob Storage | `azure` | `container`, `accountName` |

### Kubernetes CRDs

NebulaCR installs four Custom Resource Definitions for managing multi-tenant access:

| CRD | Scope | Purpose |
|-----|-------|---------|
| `Tenant` | Cluster | Top-level org with quotas, IP restrictions, OIDC mapping |
| `Project` | Namespace | Groups repositories; sets visibility, retention, scanning policies |
| `AccessPolicy` | Namespace | Fine-grained RBAC with subjects, resources, actions, conditions |
| `TokenPolicy` | Namespace | Token lifetime, rotation, revocation, robot accounts |

Example Tenant:

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Tenant
metadata:
  name: my-org
spec:
  displayName: My Organization
  adminEmail: admin@my-org.com
  quotas:
    maxStorageBytes: 107374182400  # 100 GiB
    maxRepositories: 500
    pullRatePerMinute: 1000
    pushRatePerMinute: 500
```

## CI/CD Integration

Ready-to-use examples for all major CI/CD platforms:

| Platform | Example | Auth Method |
|----------|---------|-------------|
| GitHub Actions | [`examples/github-actions/push-image.yml`](examples/github-actions/push-image.yml) | OIDC (zero secrets) |
| GitLab CI | [`examples/gitlab-ci/push-image.yml`](examples/gitlab-ci/push-image.yml) | OIDC |
| Jenkins | [`examples/jenkins/Jenkinsfile`](examples/jenkins/Jenkinsfile) | Token-based |
| Tekton | [`examples/tekton/push-task.yml`](examples/tekton/push-task.yml) | ServiceAccount |
| ArgoCD | [`examples/argocd/image-updater.yml`](examples/argocd/image-updater.yml) | Image updater |

### GitHub Actions Example

```yaml
- name: Login to NebulaCR
  uses: ./examples/github-actions/nebulacr-login-action
  with:
    registry_url: registry.example.com
    tenant: my-org
    project: my-project

- name: Push image
  run: |
    docker build -t registry.example.com/my-org/my-project/app:${{ github.sha }} .
    docker push registry.example.com/my-org/my-project/app:${{ github.sha }}
```

## Observability

### Prometheus Metrics

Enable the ServiceMonitor for automatic scraping:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --set serviceMonitor.enabled=true
```

Key metrics exposed on `/metrics`:
- `nebulacr_http_requests_total` — request count by method, path, status
- `nebulacr_http_request_duration_seconds` — request latency histogram
- `nebulacr_storage_operations_total` — storage operations by backend and type
- `nebulacr_auth_tokens_issued_total` — token issuance count

### OpenTelemetry Tracing

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --set observability.otlpEndpoint=http://otel-collector:4317 \
  --set observability.tracing.enabled=true
```

## Project Structure

```
nebulacr/
├── crates/
│   ├── nebula-auth/          # Auth service binary
│   ├── nebula-registry/      # Registry service binary
│   ├── nebula-common/        # Shared library (models, auth, storage)
│   ├── nebula-controller/    # Kubernetes CRD controller
│   ├── nebula-mirror/        # Pull-through cache engine
│   ├── nebula-resilience/    # Retry, circuit breaker, failover
│   └── nebula-replication/   # Multi-region replication
├── deploy/helm/nebulacr/     # Helm chart
├── config/                   # Example configuration
├── docs/                     # Architecture, threat model, diagrams
├── examples/                 # CI/CD integration examples
└── contrib/opsapi/           # OpsAPI metadata integration
```

## Building from Source

```bash
# Build all binaries
cargo build --workspace --release

# Run tests
cargo test --workspace

# Build Docker image
docker build -t nebulacr:latest .
```

## Security

- See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model
- See [`docs/security-audit-checklist.md`](docs/security-audit-checklist.md) for the security audit checklist
- Containers run as non-root (UID 65534) with read-only root filesystems
- All capabilities dropped, seccomp profile enforced

## Documentation

- [Architecture](docs/architecture.md)
- [System Architecture Diagrams](docs/system-architecture-diagrams.md)
- [Threat Model](docs/threat-model.md)
- [Security Audit Checklist](docs/security-audit-checklist.md)
- [Helm Chart Reference](deploy/helm/nebulacr/README.md)
- [Configuration Reference](config/nebulacr.example.toml)
- [OpsAPI Integration](contrib/opsapi/README.md)

## License

Apache-2.0
