# NebulaCR

[![Build](https://github.com/bwalia/nebulacr/actions/workflows/ci.yml/badge.svg)](https://github.com/bwalia/nebulacr/actions/workflows/ci.yml)
[![Docker Hub](https://img.shields.io/docker/v/bwalia/nebulacr?label=Docker%20Hub&sort=semver)](https://hub.docker.com/r/bwalia/nebulacr)
[![Docker Pulls](https://img.shields.io/docker/pulls/bwalia/nebulacr)](https://hub.docker.com/r/bwalia/nebulacr)
[![License](https://img.shields.io/github/license/bwalia/nebulacr)](LICENSE)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fbwalia%2Fnebulacr-blue)](https://github.com/bwalia/nebulacr/pkgs/container/nebulacr)

A cloud-native Docker/OCI container registry built in Rust with multi-tenancy, zero-trust authentication, and pull-through caching.

## Features

- **OCI Distribution API v2** compliant registry
- **Pull-through cache** for Docker Hub, GHCR, GCR, Quay.io, and registry.k8s.io
- **Multi-tenancy** with Tenant, Project, AccessPolicy, and TokenPolicy CRDs
- **Zero-trust auth** via OIDC (Google, GitHub Actions, GitLab CI, Azure AD)
- **Multiple storage backends** -- filesystem, S3, GCS, Azure Blob
- **High availability** -- stateless services, HPA, PDB, circuit breakers
- **Multi-region replication** with async/semi-sync modes
- **Observability** -- Prometheus metrics, structured JSON logging, OpenTelemetry tracing
- **Rate limiting** per IP and per tenant
- **Multi-architecture** -- linux/amd64 and linux/arm64
- **Webhook notifications** for registry events
- **Image vulnerability scanning** -- SBOM extraction, OSV + GHSA + NVD feeds, AI-assisted CVE analysis, policy gate, Slack PDF reports

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

| Service | Port | Metrics | Purpose |
|---------|------|---------|---------|
| `nebula-registry` | 5000 | 9090 | OCI Distribution API, blob/manifest storage, pull-through cache |
| `nebula-auth` | 5001 | 9091 | OIDC validation, JWT issuance, RBAC policy resolution |

## Quick Start (Local)

Run NebulaCR locally in under 5 minutes.

### Option A: Docker Run (Simplest)

```bash
docker run -d --name nebulacr -p 5000:5000 bwalia/nebulacr:latest
```

### Option B: Docker Compose (Full Stack)

```bash
git clone https://github.com/bwalia/nebulacr.git
cd nebulacr
docker compose up -d
```

This starts the registry on `localhost:5000`, auth on `localhost:5001`, and auto-generates JWT signing keys.

### Test It

```bash
# Login (default dev credentials)
docker login localhost:5000 -u admin -p admin

# Tag and push an image (2-segment path -- standard Docker)
docker tag nginx:latest localhost:5000/myorg/nginx:latest
docker push localhost:5000/myorg/nginx:latest

# Pull it back
docker pull localhost:5000/myorg/nginx:latest
```

## Quick Start (Kubernetes)

### Helm Install

```bash
# OCI registry (recommended)
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace

# Or via Helm repository
helm repo add nebulacr https://bwalia.github.io/nebulacr
helm repo update
helm install nebulacr nebulacr/nebulacr \
  --namespace nebulacr --create-namespace
```

### Verify

```bash
kubectl port-forward -n nebulacr svc/nebulacr-registry 5000:5000 &
curl http://localhost:5000/health
# {"status":"healthy"}
```

See [examples/kubernetes/](examples/kubernetes/) for minimal and HA production manifests.

## Authentication

### Docker CLI Login

```bash
# Development (bootstrap admin)
docker login registry.example.com -u admin -p admin

# Request a short-lived token via API
TOKEN=$(curl -s -u admin:admin \
  "https://registry.example.com/auth/token?service=nebulacr-registry&scope=repository:myorg/myapp:push,pull" \
  | jq -r '.token')

# Use the token
docker login registry.example.com -u token -p "$TOKEN"
```

### OIDC (Production)

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --set oidc.enabled=true \
  --set oidc.issuerUrl="https://accounts.google.com" \
  --set oidc.clientId="YOUR_CLIENT_ID" \
  --set oidc.clientSecret="YOUR_CLIENT_SECRET"
```

See [docs/authentication.md](docs/authentication.md) for full details including CI/CD integration.

## Multi-Tenant Example

NebulaCR supports both standard Docker 2-segment paths and multi-tenant 3-segment paths:

```bash
# Standard Docker (2-segment -- uses default tenant automatically)
docker tag nginx registry.example.com/myorg/nginx:latest
docker push registry.example.com/myorg/nginx:latest

# Multi-tenant (3-segment -- explicit tenant)
docker tag nginx registry.example.com/tenant-a/project-1/nginx:latest
docker push registry.example.com/tenant-a/project-1/nginx:latest
```

Manage tenants via Kubernetes CRDs:

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

See [docs/multi-tenancy.md](docs/multi-tenancy.md) for full details.

## Pull-Through Cache

Deploy NebulaCR as a caching proxy with zero configuration:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace
```

Pull images through the cache:

```bash
docker pull <nebulacr-host>:5000/library/nginx:latest       # Docker Hub
docker pull <nebulacr-host>:5000/ghcr.io/org/repo:tag       # GHCR
docker pull <nebulacr-host>:5000/quay.io/prometheus/prometheus:latest  # Quay
```

### Configure containerd Mirror

Add to `/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["http://nebulacr-registry.nebulacr.svc.cluster.local:5000"]
```

## Mirror / HA Example

NebulaCR supports multi-region replication with automatic failover:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --set registry.replicas=3 \
  --set auth.replicas=2 \
  --set multiRegion.enabled=true \
  --set multiRegion.localRegion=us-east-1 \
  --set multiRegion.isPrimary=true
```

When a region goes down, reads are automatically served from healthy replicas. See [docs/architecture.md](docs/architecture.md) for the replication model.

## Observability

### Prometheus Metrics

```bash
curl http://localhost:5000/metrics
```

Key metrics:
- `nebulacr_http_requests_total` -- request count by method, path, status
- `nebulacr_http_request_duration_seconds` -- request latency histogram
- `nebulacr_storage_operations_total` -- storage operations by backend
- `nebulacr_auth_tokens_issued_total` -- token issuance count

Enable automatic scraping with Prometheus Operator:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --set serviceMonitor.enabled=true
```

### OpenTelemetry Tracing

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --set observability.otlpEndpoint=http://otel-collector:4317 \
  --set observability.tracing.enabled=true
```

See [docs/observability.md](docs/observability.md) for Grafana dashboards and scrape configs.

## Image Vulnerability Scanning

NebulaCR ships with a built-in CVE scanner (`nebula-scanner` crate) that runs
on every push and exposes results over HTTP, WebSocket, and a dashboard panel.

### What gets scanned

| Layer | Parsers |
|---|---|
| OS packages | `dpkg` (Debian/Ubuntu), `apk` (Alpine), `rpm` (RHEL/Fedora/SUSE) |
| Language deps | `npm`, `pypi`, `cargo`, `go` modules |
| Loose binaries | ELF metadata fallback for un-packaged binaries |

The output is a CycloneDX SBOM plus a list of matched vulnerabilities.

### Vulnerability data sources

- **OSV** -- bootstrap source, queried directly for low-volume deploys.
- **NebulaVulnDb** -- local Postgres mirror ingested from OSV, GitHub
  Security Advisories (GHSA), and NVD; ecosystem-aware version matchers
  (`apk`, `deb`, `rpm`, `pep440`, `semver`, Go pseudo-versions).
- **VEX** -- ingest CycloneDX VEX statements at `POST /v2/vex` to mark
  CVEs as `not_affected` / `fixed` / `under_investigation`.

### How it works

```text
manifest push → queue → puller → SBOM extract → vulndb match
              → suppression / VEX → policy gate → Redis (1h TTL)
              → optional AI analysis (Ollama) → notify (Slack / webhook)
```

1. Each successful manifest push enqueues a scan keyed by digest.
2. The worker pulls layers from object storage and walks each tarball
   for package metadata (no shell-out to Trivy/Grype).
3. Matched CVEs are filtered through suppressions and VEX statements.
4. A policy is evaluated (`PASS` / `FAIL` + violations) and the result
   is stashed in Redis with a 1-hour TTL, keyed by digest.
5. On demand, results can be re-rendered with AI commentary
   (Ollama), exported to S3, or posted as a PR review comment.

### Scanner endpoints

| Endpoint | Purpose |
|---|---|
| `GET /v2/scan/live/{digest}` | Poll-until-complete scan result |
| `POST /v2/scan` | Trigger a scan for a `(repo, tag)` |
| `GET /v2/scan/{id}` / `/report` / `/sbom` | Result, rendered report, CycloneDX SBOM |
| `GET /v2/scan/{id}/dockerfile-fix` | AI-suggested Dockerfile remediation |
| `POST /v2/scan/{id}/pr-comment` | Post results as a GitHub PR review comment |
| `GET /v2/ws/scan/{digest}` | WebSocket progress stream |
| `GET /v2/cve/search` | Cross-image CVE search |
| `POST /v2/cve/suppress` | Manage suppressions (with audit) |
| `POST /v2/policy/evaluate` | Standalone policy evaluation |
| `POST /v2/vex` | Ingest VEX statements |
| `POST /admin/vulndb/ingest` | Trigger an OSV/GHSA/NVD ingest run |
| `POST /v2/export/s3/{id}` | Export a scan to an S3 prefix |

All `/v2/scan/**` and `/admin/**` routes accept `Authorization: Bearer
nck_<secret>` API keys with per-permission scoping; legacy unauthenticated
calls fall through as a permissive `system` principal during migration.

### Nightly scan workflows

Three workflows live in `.github/workflows/`. All publish a Slack PDF on
completion (when `SLACK_BOT_TOKEN` + `SLACK_CHANNEL_ID` are set; falls
back to a webhook text post via `SLACK_WEBHOOK_URL`).

| Workflow | Trigger | Scope |
|---|---|---|
| [`nightly-cve-scan.yml`](.github/workflows/nightly-cve-scan.yml) | Manual dispatch | Compose stack + a fixed image list -- ad-hoc smoke test |
| [`nightly-cve-scan-all.yml`](.github/workflows/nightly-cve-scan-all.yml) | Cron `17 3 * * *` + dispatch | Enumerates `/v2/_catalog` and scans every `(repo, tag)` in the registry |
| [`deploy-nightly-cve-scan.yml`](.github/workflows/deploy-nightly-cve-scan.yml) | Push to `deploy/k8s/nightly-cve-scan/**` | Deploys the in-cluster k3s `CronJob` runner -- the production schedule |

The supporting scripts -- `scripts/nightly-scan-all.sh`,
`scripts/nightly-report-pdf.py`, `scripts/slack-upload-pdf.py` -- are the
same code path the in-cluster `CronJob` runs, so failures reproduce
locally with `bash scripts/nightly-scan-all.sh`.

## Production Install

### With OIDC and S3 Storage

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
  --set pullThroughCache.upstreams.docker\\.io.username=myuser \
  --set pullThroughCache.upstreams.docker\\.io.password=mytoken
```

See [docs/deployment.md](docs/deployment.md) for all deployment options.

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

| CRD | Scope | Purpose |
|-----|-------|---------|
| `Tenant` | Cluster | Top-level org with quotas, IP restrictions, OIDC mapping |
| `Project` | Namespace | Groups repositories; sets visibility, retention, scanning policies |
| `AccessPolicy` | Namespace | Fine-grained RBAC with subjects, resources, actions, conditions |
| `TokenPolicy` | Namespace | Token lifetime, rotation, revocation, robot accounts |

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

## Docker Images

NebulaCR is published to both Docker Hub and GHCR:

```bash
# Docker Hub
docker pull bwalia/nebulacr:latest

# GitHub Container Registry
docker pull ghcr.io/bwalia/nebulacr:latest
```

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `vX.Y.Z` | Specific version |
| `X.Y` | Major.minor version |
| `edge` | Latest dev build from main |

Multi-architecture: `linux/amd64` and `linux/arm64`.

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
│   ├── nebula-replication/   # Multi-region replication
│   ├── nebula-scanner/       # CVE scanner (SBOM, vulndb match, policy, AI)
│   ├── nebula-db/            # Postgres-backed vulndb + suppression store
│   └── nebula-ai/            # Ollama client for CVE analysis + Dockerfile fixes
├── deploy/helm/nebulacr/     # Helm chart
├── config/                   # Example configuration
├── docs/                     # Documentation
├── examples/                 # CI/CD and Kubernetes examples
└── docker-compose.yml        # Local development stack
```

## Building from Source

```bash
# Build all binaries
cargo build --workspace --release

# Run tests
cargo test --workspace

# Build Docker image
docker build -t nebulacr:latest .

# Build optimized (distroless) image
docker build -f Dockerfile.scratch -t nebulacr:scratch .
```

## Documentation

- [Architecture](docs/architecture.md)
- [Authentication](docs/authentication.md)
- [Multi-Tenancy](docs/multi-tenancy.md)
- [Deployment Guide](docs/deployment.md)
- [Observability](docs/observability.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Threat Model](docs/threat-model.md)
- [Security Audit Checklist](docs/security-audit-checklist.md)
- [System Architecture Diagrams](docs/system-architecture-diagrams.md)
- [Helm Chart Reference](deploy/helm/nebulacr/README.md)
- [Configuration Reference](config/nebulacr.example.toml)

## Website

Marketing / landing page. Served by `https://nebulacr.org/` (primary),
with the S3 origin available for direct testing.

| Endpoint | URL |
|---|---|
| Primary | https://nebulacr.org/ |
| GitHub Pages | https://bwalia.github.io/nebulacr/landing/ |
| Test URL (object) | https://nebulacr-docs.s3.eu-west-2.amazonaws.com/index.html |
| S3 website | http://nebulacr-docs.s3-website.eu-west-2.amazonaws.com/ |
| Landing path | https://nebulacr-docs.s3.eu-west-2.amazonaws.com/landing/index.html |

Source: [`docs/landing/`](docs/landing/) — auto-published on `main` pushes
via [`.github/workflows/publish-landing.yml`](.github/workflows/publish-landing.yml).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and pull request guidelines.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
