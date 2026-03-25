# NebulaCR Helm Chart

Helm chart for deploying NebulaCR — a cloud-native OCI container registry with pull-through caching, multi-tenancy, and zero-trust auth.

**Chart version:** 0.2.0 | **App version:** 0.2.0 | **Kubernetes:** >= 1.25

## Install

```bash
# From OCI registry (recommended)
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace

# From Helm repository
helm repo add nebulacr https://bwalia.github.io/nebulacr
helm repo update
helm install nebulacr nebulacr/nebulacr \
  --namespace nebulacr --create-namespace
```

Default install deploys a **pull-through cache** for Docker Hub, GHCR, GCR, Quay.io, and registry.k8s.io with no additional configuration.

## Upgrade

```bash
helm upgrade nebulacr oci://ghcr.io/bwalia/charts/nebulacr --namespace nebulacr
```

## Uninstall

```bash
helm uninstall nebulacr --namespace nebulacr
```

> **Note:** CRDs are not removed on uninstall. To remove them:
> `kubectl delete crd tenants.nebulacr.io projects.nebulacr.io accesspolicies.nebulacr.io tokenpolicies.nebulacr.io`

---

## Usage Scenarios

### 1. Pull-Through Cache (Default)

Zero-config caching proxy. Install and start pulling:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr -n nebulacr --create-namespace
```

```bash
# Docker Hub images
docker pull <nebulacr-host>:5000/library/nginx:latest
docker pull <nebulacr-host>:5000/library/postgres:16

# GHCR images
docker pull <nebulacr-host>:5000/ghcr.io/actions/runner:latest

# Quay images
docker pull <nebulacr-host>:5000/quay.io/prometheus/prometheus:latest

# Kubernetes images
docker pull <nebulacr-host>:5000/registry.k8s.io/pause:3.9
```

Configure containerd on cluster nodes to use as a mirror:

```toml
# /etc/containerd/config.toml
[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["http://nebulacr-registry.nebulacr.svc.cluster.local:5000"]
```

### 2. Cache with Docker Hub Credentials

Avoid Docker Hub rate limits by providing credentials:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr -n nebulacr --create-namespace \
  --set pullThroughCache.upstreams.docker\\.io.username=myuser \
  --set pullThroughCache.upstreams.docker\\.io.password=mytoken
```

Or use an existing secret:

```bash
kubectl create secret generic dockerhub-creds -n nebulacr \
  --from-literal=username=myuser \
  --from-literal=password=mytoken

helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr -n nebulacr --create-namespace \
  --set pullThroughCache.upstreams.docker\\.io.existingSecret=dockerhub-creds
```

### 3. Private Registry with S3 Storage

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr -n nebulacr --create-namespace \
  --set pullThroughCache.enabled=false \
  --set storage.backend=s3 \
  --set storage.s3.bucket=my-registry-bucket \
  --set storage.s3.region=us-east-1 \
  --set ingress.enabled=true \
  --set ingress.host=registry.example.com \
  --set ingress.tls.enabled=true \
  --set ingress.tls.secretName=registry-tls
```

### 4. Full Production Deploy with OIDC + S3 + Monitoring

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr -n nebulacr --create-namespace \
  -f production-values.yaml
```

Example `production-values.yaml`:

```yaml
oidc:
  enabled: true
  issuerUrl: "https://accounts.google.com"
  clientId: "YOUR_CLIENT_ID"
  clientSecret: "YOUR_CLIENT_SECRET"
  tenantClaim: "hd"

storage:
  backend: s3
  s3:
    bucket: my-registry-prod
    region: us-east-1
    encrypt: true

ingress:
  enabled: true
  className: nginx
  host: registry.example.com
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
  tls:
    enabled: true
    secretName: registry-tls

serviceMonitor:
  enabled: true
  interval: 15s

observability:
  logLevel: info
  logFormat: json
  otlpEndpoint: "http://otel-collector.monitoring:4317"
  tracing:
    enabled: true
    samplingRatio: 0.1

autoscaling:
  registry:
    enabled: true
    minReplicas: 3
    maxReplicas: 20
  auth:
    enabled: true
    minReplicas: 2
    maxReplicas: 10

pullThroughCache:
  enabled: true
  ttl: 43200
  upstreams:
    docker.io:
      url: "https://registry-1.docker.io"
      existingSecret: dockerhub-creds
```

### 5. Air-Gapped / Offline Install

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr -n nebulacr --create-namespace \
  --set pullThroughCache.enabled=false \
  --set storage.backend=filesystem \
  --set storage.filesystem.persistence.size=200Gi
```

---

## Values Reference

### Global

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override fully qualified name | `""` |
| `imagePullSecrets` | Image pull secrets | `[]` |

### Registry Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `registry.image.repository` | Registry image | `ghcr.io/nebulacr/registry` |
| `registry.image.tag` | Image tag (defaults to appVersion) | `""` |
| `registry.replicas` | Replicas (ignored if HPA enabled) | `2` |
| `registry.port` | HTTP port | `5000` |
| `registry.metricsPort` | Metrics port | `9090` |
| `registry.resources.requests.cpu` | CPU request | `250m` |
| `registry.resources.requests.memory` | Memory request | `256Mi` |
| `registry.resources.limits.cpu` | CPU limit | `1` |
| `registry.resources.limits.memory` | Memory limit | `512Mi` |
| `registry.nodeSelector` | Node selector | `{}` |
| `registry.tolerations` | Tolerations | `[]` |
| `registry.affinity` | Additional affinity rules | `{}` |
| `registry.podAnnotations` | Pod annotations | `{}` |
| `registry.podLabels` | Pod labels | `{}` |
| `registry.extraEnv` | Extra environment variables | `[]` |
| `registry.extraVolumes` | Extra volumes | `[]` |
| `registry.extraVolumeMounts` | Extra volume mounts | `[]` |

### Auth Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auth.image.repository` | Auth image | `ghcr.io/nebulacr/auth` |
| `auth.image.tag` | Image tag (defaults to appVersion) | `""` |
| `auth.replicas` | Replicas (ignored if HPA enabled) | `2` |
| `auth.port` | HTTP port | `5001` |
| `auth.metricsPort` | Metrics port | `9091` |
| `auth.resources.requests.cpu` | CPU request | `100m` |
| `auth.resources.requests.memory` | Memory request | `128Mi` |
| `auth.resources.limits.cpu` | CPU limit | `500m` |
| `auth.resources.limits.memory` | Memory limit | `256Mi` |

### Pull-Through Cache

| Parameter | Description | Default |
|-----------|-------------|---------|
| `pullThroughCache.enabled` | Enable pull-through caching | `true` |
| `pullThroughCache.defaultUpstream` | Default upstream registry | `docker.io` |
| `pullThroughCache.ttl` | Cache TTL in seconds | `86400` |
| `pullThroughCache.upstreams` | Map of upstream registries | See below |

**Pre-configured upstreams:**

| Upstream | URL | Purpose |
|----------|-----|---------|
| `docker.io` | `https://registry-1.docker.io` | Docker Hub |
| `ghcr.io` | `https://ghcr.io` | GitHub Container Registry |
| `gcr.io` | `https://gcr.io` | Google Container Registry |
| `quay.io` | `https://quay.io` | Red Hat Quay |
| `registry.k8s.io` | `https://registry.k8s.io` | Kubernetes images |

Each upstream supports:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `url` | Upstream registry URL | (varies) |
| `username` | Auth username | `""` |
| `password` | Auth password/token | `""` |
| `existingSecret` | Use existing K8s secret | `""` |
| `usernameField` | Key in secret for username | `"username"` |
| `passwordField` | Key in secret for password | `"password"` |

### OIDC Authentication

| Parameter | Description | Default |
|-----------|-------------|---------|
| `oidc.enabled` | Enable OIDC auth | `false` |
| `oidc.issuerUrl` | OIDC issuer URL | `https://accounts.google.com` |
| `oidc.clientId` | OIDC client ID | `""` |
| `oidc.clientSecret` | OIDC client secret | `""` |
| `oidc.scopes` | OIDC scopes | `[openid, profile, email]` |
| `oidc.tenantClaim` | Claim for tenant mapping | `org_id` |
| `oidc.redirectUri` | Redirect URI after auth | `""` |

### JWT

| Parameter | Description | Default |
|-----------|-------------|---------|
| `jwt.existingSecret` | Use existing secret for keys | `""` |
| `jwt.signingKey` | RSA private key (base64) | `""` |
| `jwt.verificationKey` | RSA public key (base64) | `""` |
| `jwt.accessTokenTtl` | Access token lifetime (seconds) | `3600` |
| `jwt.refreshTokenTtl` | Refresh token lifetime (seconds) | `86400` |

### Storage

| Parameter | Description | Default |
|-----------|-------------|---------|
| `storage.backend` | Backend type: `filesystem`, `s3`, `gcs`, `azure` | `filesystem` |

**Filesystem:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `storage.filesystem.rootDirectory` | Data directory | `/var/lib/nebulacr/data` |
| `storage.filesystem.persistence.enabled` | Enable PVC | `true` |
| `storage.filesystem.persistence.storageClass` | Storage class | `""` |
| `storage.filesystem.persistence.accessMode` | Access mode | `ReadWriteOnce` |
| `storage.filesystem.persistence.size` | PVC size | `50Gi` |
| `storage.filesystem.persistence.existingClaim` | Use existing PVC | `""` |

**S3:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `storage.s3.bucket` | S3 bucket name | `""` |
| `storage.s3.region` | AWS region | `us-east-1` |
| `storage.s3.endpoint` | Custom endpoint (for MinIO) | `""` |
| `storage.s3.accessKey` | Access key | `""` |
| `storage.s3.secretKey` | Secret key | `""` |
| `storage.s3.existingSecret` | Use existing secret | `""` |
| `storage.s3.pathStyle` | Path-style access (for MinIO) | `false` |
| `storage.s3.encrypt` | Enable SSE | `true` |

**GCS:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `storage.gcs.bucket` | GCS bucket name | `""` |
| `storage.gcs.keyfile` | Service account JSON (base64) | `""` |
| `storage.gcs.existingSecret` | Use existing secret | `""` |

**Azure:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `storage.azure.container` | Blob container name | `""` |
| `storage.azure.accountName` | Storage account | `""` |
| `storage.azure.accountKey` | Storage account key | `""` |
| `storage.azure.existingSecret` | Use existing secret | `""` |

### Rate Limiting

| Parameter | Description | Default |
|-----------|-------------|---------|
| `rateLimiting.enabled` | Enable rate limiting | `true` |
| `rateLimiting.requestsPerSecond` | Per-IP RPS | `100` |
| `rateLimiting.burst` | Burst size | `200` |
| `rateLimiting.pullRatePerTenant` | Pulls per tenant per minute | `1000` |
| `rateLimiting.pushRatePerTenant` | Pushes per tenant per minute | `500` |

### Autoscaling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.registry.enabled` | Enable HPA for registry | `true` |
| `autoscaling.registry.minReplicas` | Min replicas | `2` |
| `autoscaling.registry.maxReplicas` | Max replicas | `10` |
| `autoscaling.registry.targetCPUUtilizationPercentage` | CPU target | `70` |
| `autoscaling.auth.enabled` | Enable HPA for auth | `true` |
| `autoscaling.auth.minReplicas` | Min replicas | `2` |
| `autoscaling.auth.maxReplicas` | Max replicas | `6` |

### Ingress

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable Ingress | `false` |
| `ingress.className` | Ingress class | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.host` | Hostname | `registry.example.com` |
| `ingress.tls.enabled` | Enable TLS | `false` |
| `ingress.tls.secretName` | TLS secret | `""` |
| `ingress.registryPath` | Registry path | `/v2` |
| `ingress.authPath` | Auth path | `/auth` |

### Observability

| Parameter | Description | Default |
|-----------|-------------|---------|
| `observability.logLevel` | Log level | `info` |
| `observability.logFormat` | Log format (`json` or `pretty`) | `json` |
| `observability.otlpEndpoint` | OTLP collector endpoint (gRPC) | `""` |
| `observability.tracing.enabled` | Enable distributed tracing | `false` |
| `observability.tracing.samplingRatio` | Trace sampling ratio | `0.1` |

### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Create Prometheus ServiceMonitor | `false` |
| `serviceMonitor.namespace` | ServiceMonitor namespace | `""` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.labels` | Extra labels | `{}` |

### Security

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create ServiceAccount | `true` |
| `serviceAccount.name` | ServiceAccount name | `""` |
| `serviceAccount.annotations` | SA annotations (for IRSA/WI) | `{}` |
| `podDisruptionBudget.registry.enabled` | Registry PDB | `true` |
| `podDisruptionBudget.registry.minAvailable` | Min available | `1` |
| `podDisruptionBudget.auth.enabled` | Auth PDB | `true` |
| `podDisruptionBudget.auth.minAvailable` | Min available | `1` |
| `networkPolicy.enabled` | Enable NetworkPolicy | `false` |

Both services run with hardened security contexts:
- `runAsNonRoot: true` (UID 65534)
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- All capabilities dropped
- `seccompProfile: RuntimeDefault`

---

## CRDs Installed

| CRD | API Group | Scope | Description |
|-----|-----------|-------|-------------|
| `Tenant` | `nebulacr.io/v1alpha1` | Cluster | Organization with quotas and IP restrictions |
| `Project` | `nebulacr.io/v1alpha1` | Namespace | Repository group with visibility and retention |
| `AccessPolicy` | `nebulacr.io/v1alpha1` | Namespace | RBAC rules with conditions (IP, time, MFA) |
| `TokenPolicy` | `nebulacr.io/v1alpha1` | Namespace | Token lifecycle, rotation, robot accounts |

---

## Troubleshooting

### Check pod status

```bash
kubectl get pods -n nebulacr
kubectl logs -n nebulacr deployment/nebulacr-registry
kubectl logs -n nebulacr deployment/nebulacr-auth
```

### Verify the registry is healthy

```bash
kubectl port-forward -n nebulacr svc/nebulacr-registry 5000:5000
curl http://localhost:5000/health
curl http://localhost:5000/v2/
```

### Check metrics

```bash
kubectl port-forward -n nebulacr svc/nebulacr-registry 9090:9090
curl http://localhost:9090/metrics
```

### Test pull-through cache

```bash
kubectl port-forward -n nebulacr svc/nebulacr-registry 5000:5000
# Should pull from Docker Hub, cache, and return
curl -I http://localhost:5000/v2/library/nginx/manifests/latest
```

---

## AI Agent Instructions

This section provides structured context for AI agents (Claude Code, Copilot, Cursor, etc.) working with this Helm chart.

### Chart location

```
deploy/helm/nebulacr/
├── Chart.yaml              # Chart metadata (version, appVersion, keywords)
├── values.yaml             # All configurable values with defaults
├── artifacthub-repo.yml    # Artifact Hub registration
├── README.md               # This file
└── templates/
    ├── _helpers.tpl         # 13 named templates (naming, labels, secrets)
    ├── configmap.yaml       # registry.yaml + auth.yaml config
    ├── secret.yaml          # JWT keys, OIDC, storage creds, upstream creds
    ├── registry-deployment.yaml  # Registry Deployment + optional PVC
    ├── auth-deployment.yaml      # Auth Deployment
    ├── registry-service.yaml     # Registry ClusterIP Service
    ├── auth-service.yaml         # Auth ClusterIP Service
    ├── ingress.yaml              # Optional Ingress
    ├── hpa.yaml                  # HPA for both services
    ├── servicemonitor.yaml       # Prometheus ServiceMonitor
    └── crds/
        ├── tenant.yaml           # Tenant CRD
        ├── project.yaml          # Project CRD
        ├── accesspolicy.yaml     # AccessPolicy CRD
        └── tokenpolicy.yaml      # TokenPolicy CRD
```

### Key patterns

- **Config flow:** `values.yaml` -> `configmap.yaml` -> mounted at `/etc/nebulacr/config/registry.yaml`
- **Secrets flow:** `values.yaml` -> `secret.yaml` -> env vars or volume mounts in deployments
- **Pull-through cache config:** rendered in `configmap.yaml` under `pull_through_cache:` key; upstream credentials injected as `<UPSTREAM>_USERNAME` / `<UPSTREAM>_PASSWORD` env vars (e.g., `DOCKER_IO_USERNAME`)
- **Helper naming:** `nebulacr.upstream.secretName` takes a list `[fullname, registryName, upstreamObj]`
- **Checksums:** Deployments include `checksum/config` and `checksum/secret` annotations to trigger rollouts on config changes
- **Version bumps:** Update `version` and `appVersion` in `Chart.yaml`; the GitHub Actions workflow at `.github/workflows/helm-release.yml` auto-publishes on push to main

### Common modification tasks

**Add a new upstream registry:**
1. Add entry under `pullThroughCache.upstreams` in `values.yaml`
2. No template changes needed — the `range` loops handle it automatically

**Add a new config field:**
1. Add default in `values.yaml`
2. Render it in `templates/configmap.yaml` under the appropriate section
3. If it's a secret, add to `templates/secret.yaml` and inject via env in the deployment

**Add a new template resource:**
1. Create `templates/<resource>.yaml`
2. Use `include "nebulacr.labels"` and `include "nebulacr.fullname"` for consistency
3. Gate with `{{- if .Values.<feature>.enabled }}`

### Testing changes

```bash
# Lint
helm lint deploy/helm/nebulacr

# Render templates (inspect output)
helm template test deploy/helm/nebulacr

# Render with custom values
helm template test deploy/helm/nebulacr --set pullThroughCache.enabled=false

# Render with credentials to verify secret generation
helm template test deploy/helm/nebulacr \
  --set 'pullThroughCache.upstreams.docker\.io.username=user' \
  --set 'pullThroughCache.upstreams.docker\.io.password=pass'

# Dry-run install against a cluster
helm install test deploy/helm/nebulacr --dry-run --debug
```
