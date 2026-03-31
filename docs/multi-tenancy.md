# Multi-Tenancy

NebulaCR provides full multi-tenancy with isolated storage, access control, quotas, and rate limiting per tenant. The tenancy model uses a three-segment repository path: `tenant/project/repository`.

## Table of Contents

- [Tenant / Project / Repository Model](#tenant--project--repository-model)
- [Default Tenant for Standard Docker Paths](#default-tenant-for-standard-docker-paths)
- [Kubernetes CRDs](#kubernetes-crds)
- [Isolation Guarantees](#isolation-guarantees)
- [Quotas and Rate Limiting](#quotas-and-rate-limiting)

---

## Tenant / Project / Repository Model

NebulaCR organizes images in a three-level hierarchy:

```
tenant / project / repository : tag
```

| Level | Description | Example |
|-------|-------------|---------|
| Tenant | Top-level organizational unit (company, team, or individual) | `acme` |
| Project | Logical grouping within a tenant (team, application, environment) | `backend` |
| Repository | A single container image | `api-server` |

Full image reference: `registry.example.com/acme/backend/api-server:v1.2.3`

This maps to the OCI Distribution path as:

```
/v2/acme/backend/api-server/manifests/v1.2.3
/v2/acme/backend/api-server/blobs/sha256:abc123...
```

### Why Three Segments?

Two-segment paths (like Docker Hub's `library/nginx`) conflate ownership and organization. The three-segment model separates concerns:

- **Tenant**: Who owns it (billing, quotas, admin boundary)
- **Project**: How it is organized (visibility, retention, access policies)
- **Repository**: What it is (a single image with tags)

---

## Default Tenant for Standard Docker Paths

For backward compatibility with standard Docker 2-segment paths, NebulaCR uses a special default tenant named `_` (underscore). When a path has only two segments, the registry automatically maps it to the `_` tenant.

```bash
# Standard 2-segment path -- tenant defaults to "_"
docker pull registry.example.com/library/nginx:latest

# Equivalent explicit 3-segment path
docker pull registry.example.com/_/library/nginx:latest
```

This is particularly useful for:

- Pull-through cache mirrors (where upstream images have 2-segment paths)
- Migration from registries that use 2-segment paths
- Simple setups where multi-tenancy is not needed

The `_` tenant is created automatically and cannot be deleted. It has default quotas and rate limits applied.

---

## Kubernetes CRDs

NebulaCR provides four Custom Resource Definitions (CRDs) in the `nebulacr.io/v1alpha1` API group. The `nebula-controller` watches these resources and syncs their state to the auth service.

### Tenant

Tenants are cluster-scoped resources (not namespaced).

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Tenant
metadata:
  name: acme
spec:
  displayName: "Acme Corporation"
  enabled: true
  # Override the global storage backend for this tenant
  storageBackend: "s3"
  # Per-tenant rate limit (requests per second)
  rateLimitRps: 200
  # Restrict access to specific IP ranges
  allowedIpRanges:
    - "10.0.0.0/8"
    - "203.0.113.0/24"
  # Resource quotas
  quotas:
    maxProjects: 50
    maxRepositories: 500
    maxStorageBytes: 107374182400   # 100 GiB
```

Check tenant status:

```bash
kubectl get tenants
kubectl describe tenant acme
```

Example status:

```
Status:
  Phase:          Ready
  Project Count:  3
  Conditions:
    Type:                  Ready
    Status:                True
    Last Transition Time:  2025-01-15T10:00:00Z
    Reason:                Reconciled
    Message:               Tenant reconciled successfully
```

### Project

Projects are namespaced resources that reference a parent tenant.

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Project
metadata:
  name: backend
  namespace: nebulacr
spec:
  tenantRef: acme
  displayName: "Backend Services"
  # "private" (default) or "public"
  visibility: private
  # Prevent overwriting of existing tags
  immutableTags: true
  # Automatic cleanup policy
  retentionPolicy:
    # Keep at most 20 tags per repository
    maxTagCount: 20
    # Delete tags older than 90 days
    expireDays: 90
```

```bash
kubectl get projects -n nebulacr
kubectl describe project backend -n nebulacr
```

### AccessPolicy

AccessPolicy defines who can do what within a tenant or project.

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: AccessPolicy
metadata:
  name: acme-backend-devs
  namespace: nebulacr
spec:
  tenantRef: acme
  # Scope to a specific project (omit for tenant-wide access)
  projectRef: backend
  subjects:
    - kind: Group
      name: "backend-developers"
    - kind: User
      name: "alice@acme.com"
    - kind: ServiceAccount
      name: "ci-bot"
  # One of: admin, maintainer, reader
  role: maintainer
  # Optional: restrict to specific actions
  actions:
    - "pull"
    - "push"
```

Roles and their permissions:

| Role | Pull | Push | Delete | Manage Projects | Manage Access |
|------|------|------|--------|-----------------|---------------|
| reader | Yes | No | No | No | No |
| maintainer | Yes | Yes | Yes | No | No |
| admin | Yes | Yes | Yes | Yes | Yes |

Subject kinds:

| Kind | Description |
|------|-------------|
| `User` | An individual user, identified by username or email |
| `Group` | A group of users (e.g., from OIDC group claims) |
| `ServiceAccount` | A CI/CD service account or bot |

### TokenPolicy

TokenPolicy controls JWT token behavior per tenant.

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: TokenPolicy
metadata:
  name: acme-token-policy
  namespace: nebulacr
spec:
  tenantRef: acme
  # Maximum allowed token lifetime
  maxTtlSeconds: 600
  # Default token lifetime when not explicitly requested
  defaultTtlSeconds: 300
  # Only issue tokens to clients in these IP ranges
  allowedIpRanges:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
  # Require MFA for token issuance (requires OIDC provider support)
  requireMfa: false
```

Validation rules enforced by the controller:

- `defaultTtlSeconds` must be less than or equal to `maxTtlSeconds`
- `maxTtlSeconds` must be greater than zero
- The referenced tenant must exist

---

## Isolation Guarantees

NebulaCR enforces strict isolation between tenants at multiple levels:

### Storage Isolation

Each tenant's data is stored under a separate prefix in the storage backend:

```
/var/lib/nebulacr/data/
  acme/
    backend/
      api-server/
        manifests/
        blobs/
    frontend/
      ...
  other-tenant/
    ...
```

For cloud storage backends (S3, GCS, Azure), tenants can optionally use separate buckets or containers by setting `storageBackend` on the Tenant CRD.

### Authentication Isolation

- Tokens are scoped to specific tenant/project/repository paths
- A token issued for `acme/backend/api-server:pull` cannot be used to access `other-tenant/...`
- Token scope is encoded in the JWT `access` claim and validated on every request

### Network Isolation

- Per-tenant IP allowlists via `allowedIpRanges` on the Tenant CRD
- Per-tenant IP restrictions on token issuance via TokenPolicy

### Namespace Isolation

- Project, AccessPolicy, and TokenPolicy CRDs are namespaced
- Kubernetes RBAC can restrict which teams can create or modify these resources

---

## Quotas and Rate Limiting

### Tenant Quotas

Set via the Tenant CRD:

```yaml
spec:
  quotas:
    maxProjects: 50           # Maximum number of projects
    maxRepositories: 500      # Maximum total repositories across all projects
    maxStorageBytes: 107374182400  # 100 GiB total storage
```

When a quota is exceeded, push operations return `429 Too Many Requests` or `403 Forbidden` with a descriptive error message.

### Rate Limiting

Rate limits are applied at multiple levels:

**Global defaults** (config file or environment variables):

```toml
[rate_limit]
default_rps = 100       # Default requests/second per tenant
ip_rps = 50             # Requests/second per IP (unauthenticated)
token_issue_rpm = 60    # Token requests/minute per tenant
```

```bash
NEBULACR_RATE_LIMIT__DEFAULT_RPS=100
NEBULACR_RATE_LIMIT__IP_RPS=50
NEBULACR_RATE_LIMIT__TOKEN_ISSUE_RPM=60
```

**Per-tenant override** via Tenant CRD:

```yaml
spec:
  rateLimitRps: 200     # This tenant gets 200 req/s instead of the default 100
```

**Helm chart values** for Kubernetes deployments:

```yaml
rateLimiting:
  enabled: true
  requestsPerSecond: 100
  burst: 200
  pullRatePerTenant: 1000    # Pulls per minute per tenant
  pushRatePerTenant: 500     # Pushes per minute per tenant
```

### Rate Limit Headers

When rate limits are approached or exceeded, the registry returns standard rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1705312200
```

When the limit is exceeded:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1
```

### Monitoring Quotas

Quota usage is exposed via Prometheus metrics:

```
nebulacr_tenant_storage_bytes{tenant="acme"}
nebulacr_tenant_repository_count{tenant="acme"}
nebulacr_tenant_project_count{tenant="acme"}
nebulacr_rate_limit_rejected_total{tenant="acme", endpoint="push"}
```

See the [Observability](observability.md) guide for setting up monitoring dashboards.
