# NebulaCR Threat Model

## 1. System Overview

NebulaCR is a cloud-native OCI-compliant container image registry built in Rust, providing multi-tenant isolation and zero-trust authentication. The system consists of two primary services and a pluggable storage backend.

### 1.1 Components

| Component         | Description                                          | Port |
|-------------------|------------------------------------------------------|------|
| nebula-registry   | OCI Distribution API (Docker Registry HTTP API V2)   | 5000 |
| nebula-auth       | Token issuance, OIDC validation, RBAC enforcement    | 5001 |
| Storage backend   | Blob/manifest persistence (filesystem, S3, GCS, Azure) | N/A |

### 1.2 Trust Boundaries

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                   TRUST BOUNDARY: CLUSTER              │
                    │                                                         │
  ┌──────────┐     │  ┌──────────────┐      ┌──────────────┐                │
  │  CI/CD   │─────┼──│  nebula-auth │──────│   OIDC       │ (external)     │
  │  Client  │     │  │  :5001       │      │   Provider   │                │
  └──────────┘     │  └──────┬───────┘      └──────────────┘                │
                    │         │ JWT                                           │
  ┌──────────┐     │  ┌──────▼───────┐      ┌──────────────┐                │
  │  Docker  │─────┼──│ nebula-      │──────│   Storage    │                │
  │  Client  │     │  │ registry     │      │   Backend    │                │
  └──────────┘     │  │  :5000       │      │  (S3/FS/GCS) │                │
                    │  └──────────────┘      └──────────────┘                │
                    │                                                         │
                    │  ┌──────────────┐                                       │
                    │  │  Prometheus  │ (metrics scrape)                      │
                    │  │  :9090       │                                       │
                    │  └──────────────┘                                       │
                    └─────────────────────────────────────────────────────────┘
```

**Trust boundary 1: External network to cluster ingress.** All client traffic crosses this boundary. TLS termination occurs here.

**Trust boundary 2: Auth service to OIDC provider.** Outbound HTTPS to validate identity tokens against the provider's JWKS endpoint.

**Trust boundary 3: Registry to storage backend.** The registry writes and reads blobs/manifests. Storage credentials are a high-value target.

**Trust boundary 4: Between tenants.** Logical isolation within the same service instance. A failure here has the highest blast radius.

---

## 2. Threat Actors

### 2.1 External Attacker

**Profile:** An unauthenticated adversary with network access to the registry or auth endpoints.

**Goals:**
- Pull private images to steal proprietary code or secrets embedded in layers
- Push malicious images to poison the supply chain
- Denial of service against the registry
- Credential harvesting via brute force or token theft

**Capabilities:** Can send arbitrary HTTP requests, may have access to public OIDC providers, can rotate source IPs.

### 2.2 Malicious Tenant

**Profile:** An authenticated user with a valid tenant who attempts to exceed their authorized scope.

**Goals:**
- Access images belonging to another tenant (cross-tenant data breach)
- Escalate privileges from Reader to Admin
- Exhaust shared resources (storage, compute) to impact other tenants
- Exfiltrate data from the storage backend via path traversal

**Capabilities:** Has valid OIDC credentials, can request tokens, can push/pull within their tenant.

### 2.3 Compromised CI/CD Pipeline

**Profile:** A CI/CD system whose credentials or OIDC trust has been abused.

**Goals:**
- Push tampered images to replace legitimate artifacts
- Use the compromised identity to pivot to other tenants
- Persist access beyond the pipeline execution window
- Exfiltrate secrets from the registry or auth service

**Capabilities:** Has a valid OIDC identity token, may have push scope, runs automated workloads.

### 2.4 Malicious Insider

**Profile:** An operator or developer with administrative access to the infrastructure.

**Goals:**
- Extract signing keys to forge tokens
- Modify access policies to grant unauthorized access
- Tamper with audit logs to cover tracks
- Access storage backend directly, bypassing the registry

**Capabilities:** May have SSH access, Kubernetes admin, or cloud IAM roles.

---

## 3. STRIDE Analysis

### 3.1 nebula-auth (Token Service)

| Threat Category    | Threat                                                    | Severity | Mitigation                                                               |
|--------------------|-----------------------------------------------------------|----------|--------------------------------------------------------------------------|
| **Spoofing**       | Forged OIDC identity token                                | Critical | Validate JWT signature against provider JWKS; pin algorithm              |
| **Spoofing**       | Replay of expired identity token                          | High     | Check `exp` claim with bounded clock skew (60s max)                      |
| **Spoofing**       | Bootstrap admin brute force                               | High     | Rate limit token endpoint; disable bootstrap admin in production         |
| **Tampering**      | Modification of issued JWT in transit                     | Critical | Sign tokens with RSA-4096/EdDSA; validate on registry side              |
| **Tampering**      | Manipulation of OIDC discovery metadata (DNS hijack)      | High     | Pin OIDC issuer URLs; use certificate pinning if possible                |
| **Repudiation**    | Deny having requested a token                             | Medium   | Log all token issuance with request ID, subject, tenant, JTI            |
| **Info Disclosure**| Token leakage via logs                                    | High     | Never log token values; redact Authorization headers                     |
| **Info Disclosure**| Signing key extraction from memory dump                   | High     | Use non-root user; restrict core dumps; consider HSM for keys            |
| **DoS**            | Token endpoint flooding                                   | High     | Per-tenant and per-IP rate limiting; separate token issuance rate limit  |
| **Elev. of Priv.** | Request token with higher role than assigned              | Critical | Resolve role server-side from policy store; ignore client-requested role |
| **Elev. of Priv.** | Request scope for another tenant's resources              | Critical | Derive tenant from access policy, not solely from request               |

### 3.2 nebula-registry (OCI Distribution API)

| Threat Category    | Threat                                                    | Severity | Mitigation                                                               |
|--------------------|-----------------------------------------------------------|----------|--------------------------------------------------------------------------|
| **Spoofing**       | Forged or stolen access token                             | Critical | Validate JWT signature and expiry on every request                       |
| **Spoofing**       | Token scope mismatch (token for repo A used on repo B)    | High     | Validate token scopes against the requested repository path              |
| **Tampering**      | Modified image manifest or layer during push              | Critical | Verify content digest matches the `Content-Type` header digest           |
| **Tampering**      | Tag mutation (overwriting a tag with a different digest)   | Medium   | Support tag immutability per project; log all tag mutations              |
| **Repudiation**    | Deny having pushed a malicious image                      | Medium   | Log push events with subject, digest, tag, and timestamp                |
| **Info Disclosure**| Pull private images without authorization                 | Critical | Validate token has `pull` scope for the specific repository             |
| **Info Disclosure**| Enumerate repositories or tags across tenants             | High     | Scope catalog/tag listing to the token's tenant and project             |
| **Info Disclosure**| Path traversal in repository name to access other data    | Critical | Validate and sanitize repository paths; reject `..` and absolute paths  |
| **DoS**            | Upload extremely large blobs to exhaust storage           | High     | Enforce per-tenant storage quotas; limit upload size per request         |
| **DoS**            | Slowloris / connection exhaustion                         | Medium   | Connection timeouts; request body size limits; reverse proxy protection  |
| **Elev. of Priv.** | Use pull token to push images                             | High     | Validate action against token scopes on every write operation            |

### 3.3 Storage Backend

| Threat Category    | Threat                                                    | Severity | Mitigation                                                               |
|--------------------|-----------------------------------------------------------|----------|--------------------------------------------------------------------------|
| **Spoofing**       | Access storage directly, bypassing the registry           | Critical | Restrict storage credentials to the registry service only; use IAM roles |
| **Tampering**      | Modify blobs directly in the storage backend              | Critical | Enable object versioning; verify digest on read                          |
| **Info Disclosure**| Read blobs from another tenant's storage prefix           | Critical | Enforce storage prefix isolation; validate tenant on every I/O operation |
| **DoS**            | Delete or corrupt storage objects                         | Critical | Use write-once storage policies; enable soft delete / versioning         |

---

## 4. Mitigations Implemented

### 4.1 Authentication Layer

1. **OIDC JWT validation** with signature verification against provider JWKS endpoints.
2. **Algorithm pinning** to RS256/EdDSA -- `none` and symmetric algorithms are rejected.
3. **Short-lived tokens** (default 300 seconds) with no refresh mechanism.
4. **Constant-time password comparison** for bootstrap admin to prevent timing attacks.
5. **Rate limiting** on token issuance (per-tenant, configurable RPM).

### 4.2 Authorization Layer

1. **Server-side role resolution** -- the client cannot request a role; it is derived from access policies.
2. **Scope intersection** -- issued token scopes are the intersection of requested and permitted actions.
3. **Tenant isolation** -- every operation is scoped to the token's tenant ID; cross-tenant access is structurally impossible in the scope model.
4. **Project-scoped policies** take precedence over tenant-wide policies.

### 4.3 Data Protection

1. **Content-addressable storage** -- blobs are stored by digest, preventing tampering.
2. **Digest verification** on upload -- pushed content must match its declared digest.
3. **Storage prefix isolation** -- each tenant's data lives under a unique prefix.
4. **No credentials in logs** -- tokens, passwords, and Authorization headers are never logged.

### 4.4 Operational Security

1. **Non-root container** -- the service runs as UID 10001.
2. **Minimal base image** -- debian-slim with no unnecessary packages.
3. **Structured JSON logging** with request IDs for full traceability.
4. **Prometheus metrics** for monitoring authentication failures, rate limits, and request patterns.
5. **Health check endpoints** for liveness and readiness probing.

---

## 5. Residual Risks

These are known risks that are accepted or require external mitigation.

### 5.1 Accepted Risks

| Risk                                            | Severity | Rationale                                                                 |
|-------------------------------------------------|----------|---------------------------------------------------------------------------|
| In-memory signing key (no HSM)                  | Medium   | HSM integration adds significant complexity; mitigated by non-root user, restricted file permissions, and key rotation |
| Single-process token issuance (no quorum)       | Medium   | Acceptable for most deployments; HA is achieved via horizontal scaling behind a load balancer |
| OIDC provider availability dependency           | Medium   | If the OIDC provider is down, no new tokens can be issued; existing tokens remain valid until expiry |
| Tag mutability (default)                         | Low      | Tag immutability is configurable per project; mutable tags are the Docker ecosystem default |

### 5.2 Risks Requiring External Mitigation

| Risk                                            | Severity | Required External Control                                                 |
|-------------------------------------------------|----------|---------------------------------------------------------------------------|
| TLS termination                                 | Critical | Deploy behind a TLS-terminating reverse proxy or ingress controller       |
| Storage backend access control                  | Critical | Configure cloud IAM to restrict storage access to the registry service account only |
| Network segmentation                            | High     | Use Kubernetes NetworkPolicies or cloud VPC rules to restrict traffic     |
| Log tampering                                   | Medium   | Ship logs to an immutable, centralized logging system (e.g., Loki, CloudWatch) |
| DDoS protection                                 | High     | Use a cloud WAF or DDoS mitigation service in front of the registry      |
| Signing key backup and recovery                 | High     | Store key backups in a secrets manager with access audit trail            |

### 5.3 Future Improvements

1. **JWKS caching with background refresh** to reduce latency and OIDC provider dependency.
2. **Token revocation list (JTI blacklist)** for emergency token invalidation.
3. **Mutual TLS (mTLS)** between auth and registry services.
4. **Hardware Security Module (HSM)** integration for signing key protection.
5. **Content trust / Notation integration** for mandatory image signing.
6. **Per-tenant storage quotas** with enforcement at the registry layer.
7. **Audit log streaming** to an external SIEM.

---

## 6. Review History

| Date       | Reviewer | Changes                           |
|------------|----------|-----------------------------------|
|            |          | Initial threat model              |
