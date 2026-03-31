# Deployment

This guide covers deploying NebulaCR in Docker (single container and docker-compose), Kubernetes with Helm, and the associated configuration for storage backends, TLS, and ingress.

## Table of Contents

- [Docker](#docker)
- [Kubernetes with Helm](#kubernetes-with-helm)
- [Storage Backend Configuration](#storage-backend-configuration)
- [TLS and Ingress Setup](#tls-and-ingress-setup)
- [Environment Variables Reference](#environment-variables-reference)

---

## Docker

### Single Container (Quick Test)

For a quick test, you can run the registry and auth services from the same image:

```bash
# Generate JWT signing keys
mkdir -p keys
openssl genrsa -out keys/private.pem 4096
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Run the auth service
docker run -d --name nebula-auth \
  -p 5001:5001 \
  -v $(pwd)/keys:/etc/nebulacr/keys \
  -e RUST_LOG=info \
  -e NEBULACR_SERVER__AUTH_LISTEN_ADDR=0.0.0.0:5001 \
  -e NEBULACR_AUTH__ISSUER=nebulacr \
  -e NEBULACR_AUTH__AUDIENCE=nebulacr-registry \
  -e NEBULACR_AUTH__SIGNING_ALGORITHM=RS256 \
  -e NEBULACR_AUTH__SIGNING_KEY_PATH=/etc/nebulacr/keys/private.pem \
  -e NEBULACR_AUTH__VERIFICATION_KEY_PATH=/etc/nebulacr/keys/public.pem \
  -e NEBULACR_AUTH__TOKEN_TTL_SECONDS=300 \
  -e NEBULACR_AUTH__BOOTSTRAP_ADMIN__USERNAME=admin \
  -e 'NEBULACR_AUTH__BOOTSTRAP_ADMIN__PASSWORD_HASH=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918' \
  ghcr.io/bwalia/nebulacr:latest nebula-auth

# Run the registry service
docker run -d --name nebula-registry \
  -p 5000:5000 -p 9090:9090 \
  -v $(pwd)/keys:/etc/nebulacr/keys:ro \
  -v nebulacr-data:/var/lib/nebulacr/data \
  -e RUST_LOG=info \
  -e NEBULACR_SERVER__LISTEN_ADDR=0.0.0.0:5000 \
  -e NEBULACR_SERVER__METRICS_ADDR=0.0.0.0:9090 \
  -e NEBULACR_AUTH__ISSUER=nebulacr \
  -e NEBULACR_AUTH__AUDIENCE=nebulacr-registry \
  -e NEBULACR_AUTH__SIGNING_ALGORITHM=RS256 \
  -e NEBULACR_AUTH__VERIFICATION_KEY_PATH=/etc/nebulacr/keys/public.pem \
  -e NEBULACR_STORAGE__BACKEND=filesystem \
  -e NEBULACR_STORAGE__ROOT=/var/lib/nebulacr/data \
  ghcr.io/bwalia/nebulacr:latest nebula-registry
```

### Docker Compose (Recommended for Development)

The repository includes a full `docker-compose.yml`:

```bash
# Start all services (registry + auth + key generation)
docker compose up -d

# Verify health
curl http://localhost:5000/health
curl http://localhost:5001/health

# Login and push
docker login localhost:5000 -u admin -p admin
docker tag myimage:latest localhost:5000/demo/default/myimage:latest
docker push localhost:5000/demo/default/myimage:latest
```

To include MinIO for S3-compatible storage:

```bash
docker compose --profile minio up -d
```

Then set the registry to use MinIO by adding these environment variables to the registry service:

```bash
NEBULACR_STORAGE__BACKEND=minio
NEBULACR_STORAGE__ROOT=nebulacr
NEBULACR_STORAGE__ENDPOINT=http://minio:9000
NEBULACR_STORAGE__ACCESS_KEY=minioadmin
NEBULACR_STORAGE__SECRET_KEY=minioadmin
```

### Stopping and Cleaning Up

```bash
# Stop services
docker compose down

# Stop and remove all data
docker compose down -v
```

---

## Kubernetes with Helm

NebulaCR provides a Helm chart published to GHCR:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr
```

Or from the local chart:

```bash
helm install nebulacr ./deploy/helm/nebulacr
```

### Minimal Install (Pull-Through Cache)

The default values enable pull-through caching for Docker Hub, GHCR, GCR, Quay.io, and registry.k8s.io with no auth configuration required:

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace
```

Configure your container runtime to use NebulaCR as a mirror. For containerd (`/etc/containerd/config.toml`):

```toml
[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["http://nebulacr-registry.nebulacr.svc.cluster.local:5000"]
```

### Production with OIDC + S3

```bash
helm install nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr --create-namespace \
  --values production-values.yaml
```

`production-values.yaml`:

```yaml
registry:
  replicas: 3
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: "2"
      memory: 1Gi

auth:
  replicas: 3
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: "1"
      memory: 512Mi

oidc:
  enabled: true
  issuerUrl: "https://accounts.google.com"
  clientId: "your-client-id.apps.googleusercontent.com"
  clientSecret: "your-client-secret"
  tenantClaim: "hd"
  scopes:
    - openid
    - profile
    - email

jwt:
  existingSecret: "nebulacr-jwt-keys"
  accessTokenTtl: 300

storage:
  backend: s3
  s3:
    bucket: "my-nebulacr-bucket"
    region: "us-east-1"
    existingSecret: "nebulacr-s3-credentials"
    encrypt: true

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  host: registry.example.com
  tls:
    enabled: true
    secretName: registry-tls

serviceMonitor:
  enabled: true
  interval: 30s

rateLimiting:
  enabled: true
  requestsPerSecond: 200
  burst: 400

autoscaling:
  registry:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
  auth:
    enabled: true
    minReplicas: 3
    maxReplicas: 6

podDisruptionBudget:
  registry:
    enabled: true
    minAvailable: 2
  auth:
    enabled: true
    minAvailable: 2
```

Create the required secrets before installing:

```bash
# JWT signing keys
kubectl create secret generic nebulacr-jwt-keys \
  --namespace nebulacr \
  --from-file=private.pem=./keys/private.pem \
  --from-file=public.pem=./keys/public.pem

# S3 credentials (if not using IRSA)
kubectl create secret generic nebulacr-s3-credentials \
  --namespace nebulacr \
  --from-literal=access-key=AKIAIOSFODNN7EXAMPLE \
  --from-literal=secret-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### High Availability (Multi-Region)

```yaml
multiRegion:
  enabled: true
  localRegion: "us-east-1"
  healthCheckIntervalSecs: 10
  internalPort: 5002
  replication:
    mode: "async"
    maxLagSecs: 60
    batchSize: 50
    sweepIntervalSecs: 10
  regions:
    - name: "us-east-1"
      endpoint: "https://registry-us.example.com"
      internalEndpoint: "http://registry-us-internal:5002"
      isPrimary: true
      priority: 1
    - name: "eu-west-1"
      endpoint: "https://registry-eu.example.com"
      internalEndpoint: "http://registry-eu-internal:5002"
      isPrimary: false
      priority: 2
```

### Using IRSA (AWS) or Workload Identity (GCP)

Instead of static S3 credentials, use IAM Roles for Service Accounts:

```yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/nebulacr"

storage:
  backend: s3
  s3:
    bucket: "my-nebulacr-bucket"
    region: "us-east-1"
    # No accessKey/secretKey needed -- IRSA provides credentials
```

### Upgrading

```bash
helm upgrade nebulacr oci://ghcr.io/bwalia/charts/nebulacr \
  --namespace nebulacr \
  --values production-values.yaml
```

---

## Storage Backend Configuration

### Filesystem

Best for development and single-node deployments:

```toml
[storage]
backend = "filesystem"
root = "/var/lib/nebulacr/data"
```

Helm values:

```yaml
storage:
  backend: filesystem
  filesystem:
    rootDirectory: /var/lib/nebulacr/data
    persistence:
      enabled: true
      storageClass: "gp3"
      size: 100Gi
```

### Amazon S3

```toml
[storage]
backend = "s3"
root = "my-nebulacr-bucket"
region = "us-east-1"
# For non-AWS S3-compatible services:
# endpoint = "https://s3.us-east-1.amazonaws.com"
# For static credentials (prefer IAM roles):
# access_key = "AKIAIOSFODNN7EXAMPLE"
# secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

Helm values:

```yaml
storage:
  backend: s3
  s3:
    bucket: "my-nebulacr-bucket"
    region: "us-east-1"
    encrypt: true
    sseAlgorithm: "AES256"
    existingSecret: "nebulacr-s3-credentials"
```

### MinIO (S3-compatible)

```toml
[storage]
backend = "minio"
root = "nebulacr"
endpoint = "http://minio:9000"
access_key = "minioadmin"
secret_key = "minioadmin"
```

The `minio` backend automatically enables path-style addressing and allows HTTP connections.

### Google Cloud Storage

```toml
[storage]
backend = "gcs"
root = "my-nebulacr-bucket"
```

GCS uses Application Default Credentials. On GKE, use Workload Identity. For local development, set `GOOGLE_APPLICATION_CREDENTIALS`.

Helm values:

```yaml
storage:
  backend: gcs
  gcs:
    bucket: "my-nebulacr-bucket"
    existingSecret: "nebulacr-gcs-keyfile"
    keyfileField: "keyfile.json"
```

### Azure Blob Storage

```toml
[storage]
backend = "azure"
root = "my-nebulacr-container"
```

Helm values:

```yaml
storage:
  backend: azure
  azure:
    container: "my-nebulacr-container"
    accountName: "myaccount"
    existingSecret: "nebulacr-azure-credentials"
    accountKeyField: "account-key"
```

---

## TLS and Ingress Setup

### Kubernetes Ingress with nginx and cert-manager

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    # Required: Docker push can send arbitrarily large layers
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    # Recommended: large layers need time to upload
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
    # TLS via cert-manager
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  host: registry.example.com
  tls:
    enabled: true
    secretName: registry-tls
  # Path routing
  registryPath: /v2
  authPath: /auth
  # Security: only expose token and JWKS endpoints
  security:
    exposeAllAuthPaths: false
    exposeGitHubActions: false
```

Important nginx annotations for container registries:

| Annotation | Value | Purpose |
|-----------|-------|---------|
| `proxy-body-size` | `"0"` | Disable body size limit for layer uploads |
| `proxy-read-timeout` | `"600"` | Allow 10 minutes for large layer transfers |
| `proxy-send-timeout` | `"600"` | Allow 10 minutes for large layer transfers |
| `proxy-buffering` | `"off"` | Stream large responses without buffering |

### Self-Signed TLS for Development

```bash
# Generate a self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt \
  -days 365 -nodes -subj "/CN=registry.local"

# Create Kubernetes secret
kubectl create secret tls registry-tls \
  --cert=tls.crt --key=tls.key \
  --namespace nebulacr
```

To use self-signed certificates with Docker, add the certificate to Docker's trusted certificates:

```bash
# Linux
sudo mkdir -p /etc/docker/certs.d/registry.local:5000
sudo cp tls.crt /etc/docker/certs.d/registry.local:5000/ca.crt
sudo systemctl restart docker

# macOS (Docker Desktop)
# Add tls.crt to Keychain Access, then restart Docker Desktop
```

### TLS Without Ingress (Direct TLS Termination)

If you prefer to terminate TLS at the service level rather than at the ingress, mount certificates directly and configure the services:

```yaml
registry:
  extraVolumes:
    - name: tls
      secret:
        secretName: registry-tls
  extraVolumeMounts:
    - name: tls
      mountPath: /etc/nebulacr/tls
      readOnly: true
  extraEnv:
    - name: NEBULACR_SERVER__TLS_CERT_PATH
      value: /etc/nebulacr/tls/tls.crt
    - name: NEBULACR_SERVER__TLS_KEY_PATH
      value: /etc/nebulacr/tls/tls.key
```

---

## Environment Variables Reference

All configuration options can be set via environment variables. The prefix is `NEBULACR_` and nesting uses double underscores (`__`).

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `NEBULACR_SERVER__LISTEN_ADDR` | `0.0.0.0:5000` | Registry API bind address |
| `NEBULACR_SERVER__AUTH_LISTEN_ADDR` | `0.0.0.0:5001` | Auth service bind address |
| `NEBULACR_SERVER__METRICS_ADDR` | `0.0.0.0:9090` | Prometheus metrics bind address |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `NEBULACR_AUTH__SIGNING_ALGORITHM` | `RS256` | JWT signing algorithm (`RS256` or `EdDSA`) |
| `NEBULACR_AUTH__SIGNING_KEY_PATH` | `/etc/nebulacr/keys/private.pem` | Path to private signing key |
| `NEBULACR_AUTH__VERIFICATION_KEY_PATH` | `/etc/nebulacr/keys/public.pem` | Path to public verification key |
| `NEBULACR_AUTH__TOKEN_TTL_SECONDS` | `300` | Access token lifetime in seconds |
| `NEBULACR_AUTH__ISSUER` | `nebulacr` | JWT issuer claim |
| `NEBULACR_AUTH__AUDIENCE` | `nebulacr-registry` | JWT audience claim |
| `NEBULACR_AUTH__BOOTSTRAP_ADMIN__USERNAME` | (none) | Bootstrap admin username |
| `NEBULACR_AUTH__BOOTSTRAP_ADMIN__PASSWORD_HASH` | (none) | Bootstrap admin password SHA-256 hash |

### Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `NEBULACR_STORAGE__BACKEND` | `filesystem` | Backend type: `filesystem`, `s3`, `minio`, `gcs`, `azure` |
| `NEBULACR_STORAGE__ROOT` | `/var/lib/nebulacr/data` | Root path or bucket name |
| `NEBULACR_STORAGE__ENDPOINT` | (none) | S3-compatible endpoint URL |
| `NEBULACR_STORAGE__REGION` | (none) | AWS region for S3 |
| `NEBULACR_STORAGE__ACCESS_KEY` | (none) | Static access key for S3/MinIO |
| `NEBULACR_STORAGE__SECRET_KEY` | (none) | Static secret key for S3/MinIO |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level filter (tracing env-filter syntax) |
| `NEBULACR_OBSERVABILITY__LOG_LEVEL` | `info` | Log level |
| `NEBULACR_OBSERVABILITY__LOG_FORMAT` | `json` | Log format: `json` or `pretty` |
| `NEBULACR_OBSERVABILITY__OTLP_ENDPOINT` | (none) | OpenTelemetry OTLP collector endpoint |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `NEBULACR_RATE_LIMIT__DEFAULT_RPS` | `100` | Default requests/second per tenant |
| `NEBULACR_RATE_LIMIT__IP_RPS` | `50` | Requests/second per IP (unauthenticated) |
| `NEBULACR_RATE_LIMIT__TOKEN_ISSUE_RPM` | `60` | Token issuance requests/minute per tenant |

### Configuration Loading Order

Configuration is loaded in this order (later sources override earlier):

1. Compiled defaults
2. Config file (`/etc/nebulacr/config.toml` or path from `NEBULACR_CONFIG_PATH`)
3. Environment variables (prefixed with `NEBULACR_`, double-underscore for nesting)
