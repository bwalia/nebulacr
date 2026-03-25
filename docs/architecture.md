# NebulaCR Architecture

## 1. System Components

NebulaCR is a Rust workspace with three crates that compile into two binaries.

```
nebulacr/
├── crates/
│   ├── nebula-common/    Shared library: models, config, auth types, storage helpers
│   ├── nebula-auth/      Binary: token issuance service (port 5001)
│   └── nebula-registry/  Binary: OCI Distribution API service (port 5000)
├── config/               Example configuration files
├── deploy/               Helm charts and Kubernetes manifests
├── docs/                 Architecture, threat model, security checklist
└── examples/             CI/CD integration examples
```

### 1.1 nebula-common

Shared library crate containing:

- **Models** -- Tenant, Project, Repository, Manifest, Descriptor, RBAC types (Role, Action, AccessPolicy)
- **Auth types** -- TokenClaims, TokenRequest/Response, OidcProviderConfig, DockerTokenResponse
- **Config** -- RegistryConfig with sections for server, auth, storage, observability, and rate limiting
- **Storage helpers** -- Path builders for blobs, manifests, tags, and uploads following the layout `<tenant>/<project>/<repo>/<type>/<reference>`
- **Error types** -- Structured error enum (RegistryError) that maps to HTTP status codes

### 1.2 nebula-auth

Stateless token issuance service built on Axum. Responsibilities:

- Validate OIDC identity tokens against provider JWKS endpoints
- Authenticate bootstrap admin via Basic auth (development/initial setup only)
- Resolve RBAC policies to determine the caller's role within a tenant/project
- Issue short-lived JWTs (default 5 minutes) signed with RS256 or EdDSA
- Expose Docker-compatible `GET /auth/token` endpoint for `docker login` flows
- Rate limit token issuance per tenant

Endpoints:
| Method | Path           | Description                              |
|--------|----------------|------------------------------------------|
| POST   | /auth/token    | Exchange identity token for access token |
| GET    | /auth/token    | Docker-compatible token endpoint         |
| GET    | /health        | Health check                             |
| GET    | /metrics       | Prometheus metrics                       |

### 1.3 nebula-registry

OCI Distribution Specification implementation built on Axum with `object_store` for pluggable storage backends. Responsibilities:

- Serve the Docker Registry HTTP API V2
- Validate access tokens (JWTs) on every request
- Enforce tenant isolation and scope-based authorization
- Manage blob uploads (monolithic and chunked)
- Store and retrieve manifests and tags
- Content-addressable storage with digest verification

Endpoints:
| Method      | Path                                             | Description              |
|-------------|--------------------------------------------------|--------------------------|
| GET         | /v2/                                             | API version check        |
| HEAD/GET    | /v2/{name}/manifests/{reference}                 | Get manifest             |
| PUT         | /v2/{name}/manifests/{reference}                 | Put manifest             |
| DELETE      | /v2/{name}/manifests/{reference}                 | Delete manifest          |
| HEAD/GET    | /v2/{name}/blobs/{digest}                        | Get blob                 |
| POST        | /v2/{name}/blobs/uploads/                        | Initiate blob upload     |
| PATCH       | /v2/{name}/blobs/uploads/{uuid}                  | Upload blob chunk        |
| PUT         | /v2/{name}/blobs/uploads/{uuid}                  | Complete blob upload     |
| GET         | /v2/{name}/tags/list                             | List tags                |
| GET         | /v2/_catalog                                     | List repositories        |

---

## 2. Authentication Flow

### 2.1 Zero-Trust Auth with OIDC

NebulaCR implements a zero-trust authentication model. No long-lived secrets are stored. CI/CD systems and users authenticate using OIDC identity tokens from trusted providers (GitHub Actions, GitLab CI, Google, Azure AD, etc.).

```
┌──────────┐       ┌──────────────┐       ┌──────────────┐
│  CI/CD   │       │  OIDC        │       │  nebula-auth │
│  Runner  │       │  Provider    │       │  :5001       │
└────┬─────┘       └──────┬───────┘       └──────┬───────┘
     │                     │                      │
     │  1. Request ID token│                      │
     │────────────────────>│                      │
     │                     │                      │
     │  2. ID token (JWT)  │                      │
     │<────────────────────│                      │
     │                     │                      │
     │  3. POST /auth/token (ID token + scope)    │
     │────────────────────────────────────────────>│
     │                     │                      │
     │                     │  4. Fetch JWKS       │
     │                     │<─────────────────────│
     │                     │                      │
     │                     │  5. JWKS response    │
     │                     │─────────────────────>│
     │                     │                      │
     │                     │       6. Validate ID token signature
     │                     │          Resolve tenant + role
     │                     │          Intersect requested scopes
     │                     │          Sign access token (RS256)
     │                     │                      │
     │  7. Access token (JWT, 5 min TTL)          │
     │<────────────────────────────────────────────│
     │                     │                      │
```

### 2.2 Docker Login Flow

Standard Docker clients use the token authentication protocol defined by the Docker Registry specification.

```
┌──────────┐       ┌──────────────┐       ┌──────────────┐
│  Docker  │       │ nebula-      │       │  nebula-auth │
│  Client  │       │ registry     │       │  :5001       │
└────┬─────┘       │  :5000       │       └──────┬───────┘
     │              └──────┬───────┘              │
     │  1. GET /v2/        │                      │
     │────────────────────>│                      │
     │                     │                      │
     │  2. 401 Unauthorized│                      │
     │     WWW-Authenticate: Bearer               │
     │       realm="https://auth:5001/auth/token" │
     │       service="nebulacr-registry"           │
     │       scope="repository:tenant/proj/repo:pull"
     │<────────────────────│                      │
     │                     │                      │
     │  3. GET /auth/token?scope=...&service=...  │
     │     Authorization: Basic <base64>          │
     │────────────────────────────────────────────>│
     │                     │                      │
     │  4. {"token": "...", "expires_in": 300}    │
     │<────────────────────────────────────────────│
     │                     │                      │
     │  5. GET /v2/tenant/proj/repo/manifests/tag │
     │     Authorization: Bearer <access-token>   │
     │────────────────────>│                      │
     │                     │                      │
     │               6. Validate JWT              │
     │                  Check scopes              │
     │                  Serve manifest            │
     │                     │                      │
     │  7. 200 OK + manifest                      │
     │<────────────────────│                      │
```

### 2.3 Token Issuance Sequence

```
POST /auth/token
{
  "identity_token": "<OIDC JWT from provider>",
  "scope": {
    "tenant": "acme",
    "project": "backend",
    "repository": "api-server",
    "actions": ["pull", "push"]
  }
}

Auth Service Processing:
  1. Rate limit check (per-tenant RPM)
  2. Validate identity token:
     a. Decode JWT header and payload
     b. Fetch OIDC provider JWKS (cached)
     c. Verify signature (RS256/EdDSA)
     d. Check exp, iss, aud claims
     e. Extract subject from sub claim
  3. Resolve tenant by name -> tenant ID
  4. Check tenant is enabled
  5. Resolve project by name within tenant -> project ID
  6. Look up access policies for (subject, tenant_id, project_id)
  7. Determine role: Admin > Maintainer > Reader
  8. Intersect requested actions with role permissions
  9. Build token claims (iss, sub, aud, exp, iat, jti, tenant_id, project_id, role, scopes)
 10. Sign JWT with RSA private key
 11. Return token + expiry

Response:
{
  "token": "<signed JWT>",
  "expires_in": 300,
  "issued_at": "2026-03-24T12:00:00Z"
}
```

---

## 3. Storage Layout

NebulaCR uses a hierarchical content-addressable storage layout. The storage backend is pluggable via the `object_store` crate (filesystem, S3, GCS, Azure Blob).

```
<storage_root>/
└── <tenant>/                          # Tenant isolation at the top level
    └── <project>/                     # Project grouping
        └── <repository>/              # Individual image repository
            ├── blobs/
            │   └── sha256/
            │       ├── <digest-hex>   # Image layer data (content-addressed)
            │       └── ...
            ├── manifests/
            │   ├── <digest>           # Manifest by digest
            │   └── ...
            ├── tags/
            │   ├── latest             # Tag -> digest link file
            │   ├── v1.0.0             # Content: "sha256:<digest>"
            │   └── ...
            └── uploads/
                ├── <uuid>             # In-progress upload session
                └── ...
```

### Key design decisions:

- **Tenant at root level** ensures storage-level isolation. A misconfigured query cannot cross tenant boundaries because the path prefix is different.
- **Content-addressable blobs** are stored by their SHA-256 digest. Identical layers across repositories within the same tenant are candidates for deduplication.
- **Tags are symlink-like files** that contain the digest of the manifest they point to. This allows atomic tag updates and easy tag listing.
- **Upload sessions** are temporary objects that are cleaned up after completion or timeout.

---

## 4. Multi-Tenancy Model

### 4.1 Tenant Hierarchy

```
Tenant (org-level)
├── Project A
│   ├── Repository 1
│   ├── Repository 2
│   └── ...
├── Project B
│   └── ...
└── ...
```

- **Tenant**: Top-level organizational unit (company, team, or department). Has its own storage prefix, rate limits, and user policies.
- **Project**: A grouping within a tenant. Controls visibility (public/private) and can have project-scoped access policies.
- **Repository**: An individual image repository within a project. Named as `<tenant>/<project>/<repo>` in the Docker namespace.

### 4.2 Isolation Guarantees

| Dimension        | Isolation Mechanism                                           |
|------------------|---------------------------------------------------------------|
| Authentication   | Tokens are scoped to a single tenant; cross-tenant tokens cannot be issued |
| Authorization    | Access policies are tenant-scoped; role resolution checks tenant_id match  |
| Storage          | Each tenant has a unique storage prefix; path construction enforces it     |
| Rate limiting    | Per-tenant rate limiters prevent noisy-neighbor effects                     |
| Metrics          | Metrics are labeled by tenant for per-tenant monitoring                    |

### 4.3 RBAC Model

Roles are hierarchical. Higher roles inherit all permissions of lower roles.

```
Admin
  ├── pull, push, delete, tag, manage
  └── Can manage access policies, projects, and repository settings
Maintainer
  ├── pull, push, delete, tag
  └── Can push images and manage tags
Reader
  └── pull
      Can only pull images
```

Access policies bind a subject (user identity from OIDC `sub` claim) to a role within a scope:

- **Tenant-wide policy**: Applies to all projects in the tenant (project_id = None)
- **Project-scoped policy**: Applies to a specific project (takes precedence over tenant-wide)

Default: authenticated users with no explicit policy get the Reader role.

---

## 5. High Availability and Scaling

### 5.1 Stateless Services

Both `nebula-auth` and `nebula-registry` are designed to be stateless (or near-stateless):

- **nebula-auth**: All state (tenants, projects, policies) is currently in-memory. For production HA, this will be backed by a shared database (PostgreSQL) or distributed cache.
- **nebula-registry**: Storage is delegated to the object store backend. No local state beyond in-flight uploads.

### 5.2 Horizontal Scaling

```
                     ┌─────────────────┐
                     │  Load Balancer  │
                     │  (L7 / Ingress) │
                     └────────┬────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
        ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
        │ registry-0│  │ registry-1│  │ registry-2│
        └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
              │               │               │
              └───────────────┼───────────────┘
                              │
                     ┌────────▼────────┐
                     │  Object Store   │
                     │  (S3/GCS/Azure) │
                     └─────────────────┘
```

- **Registry replicas** can scale horizontally because storage is external. A load balancer distributes requests across replicas.
- **Auth replicas** can scale horizontally once backed by a shared policy store. All replicas use the same signing key.
- **Upload sessions** require sticky sessions or a shared upload state store for chunked uploads spanning multiple requests.

### 5.3 Deployment Topology

**Recommended production deployment (Kubernetes):**

| Component      | Replicas | Resource Profile       | Notes                         |
|----------------|----------|------------------------|-------------------------------|
| nebula-auth    | 2-3      | 256Mi RAM, 0.5 CPU     | Behind internal ClusterIP     |
| nebula-registry| 3-5      | 512Mi-1Gi RAM, 1 CPU   | Behind Ingress with TLS       |
| Object store   | N/A      | Managed (S3/GCS)       | Cross-AZ replication          |
| PostgreSQL     | 2-3      | 1Gi RAM, 1 CPU         | For policy/tenant state (future) |

### 5.4 Failure Modes

| Failure                  | Impact                                      | Recovery                                    |
|--------------------------|---------------------------------------------|---------------------------------------------|
| Auth service down        | No new tokens; existing tokens still valid   | Horizontal scaling + health checks          |
| Registry replica down    | Reduced throughput; LB routes around it      | Auto-restart via K8s; no data loss           |
| Storage backend down     | All push/pull operations fail                | Depends on backend HA (S3: 99.99% SLA)      |
| OIDC provider down       | No new identity tokens; no new auth          | Cached JWKS allows validation of recent tokens |
| Signing key lost         | Cannot issue new tokens; existing still valid| Restore from backup; rotate after max TTL    |

---

## 6. Observability

### 6.1 Metrics (Prometheus)

Both services expose a `/metrics` endpoint on port 9090 with:

- `registry_auth_requests_total` -- Total authentication attempts
- `registry_token_issued_total` -- Tokens successfully issued
- `registry_auth_failures_total{reason}` -- Authentication failures by reason
- `registry_http_requests_total{method,path,status}` -- HTTP request counts
- `registry_http_request_duration_seconds` -- Request latency histograms
- `registry_blob_upload_bytes_total` -- Bytes uploaded
- `registry_storage_operations_total{op,status}` -- Storage backend operations

### 6.2 Structured Logging

All log output is structured JSON with the following fields:

```json
{
  "timestamp": "2026-03-24T12:00:00.000Z",
  "level": "INFO",
  "target": "nebula_auth::handlers",
  "message": "token issued",
  "request_id": "a1b2c3d4-...",
  "subject": "repo:org/repo:ref:refs/heads/main",
  "tenant_id": "uuid",
  "role": "maintainer",
  "file": "src/main.rs",
  "line": 420
}
```

### 6.3 Distributed Tracing

OpenTelemetry traces are exported via OTLP to a configured collector (Jaeger, Tempo, etc.). Each request generates a trace span with:

- HTTP method, path, status code
- Authentication result (success/failure + reason)
- Tenant and project context
- Storage backend operation timing
