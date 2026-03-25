# NebulaCR Security Audit Checklist

This document provides a comprehensive security audit checklist for NebulaCR deployments. Each item should be verified before going to production and re-checked on a regular cadence (quarterly recommended).

---

## 1. Authentication

### 1.1 OIDC Provider Configuration

- [ ] All OIDC providers use HTTPS issuer URLs (no plain HTTP)
- [ ] OIDC provider JWKS endpoints are reachable and certs are valid
- [ ] `client_id` values are unique per deployment environment (dev/staging/prod)
- [ ] `client_secret` (if used) is stored in a secrets manager, not in config files
- [ ] Only trusted OIDC issuers are configured (no wildcards or open providers)
- [ ] OIDC discovery metadata is cached with a bounded TTL (not indefinitely)

### 1.2 JWT Validation

- [ ] All incoming JWTs are validated against the provider's JWKS (not skipped)
- [ ] JWT signature algorithm is pinned (`RS256` or `EdDSA`) -- `none` algorithm is rejected
- [ ] The `aud` (audience) claim is validated against the expected value
- [ ] The `iss` (issuer) claim is validated against the configured provider URL
- [ ] The `exp` (expiry) claim is checked with no more than 60 seconds of clock skew tolerance
- [ ] The `nbf` (not before) claim is checked if present
- [ ] The `sub` (subject) claim is non-empty and used for identity resolution

### 1.3 Token Issuance

- [ ] Issued access tokens have a short TTL (default: 300 seconds / 5 minutes)
- [ ] Tokens contain the minimum necessary claims (tenant, project, scopes)
- [ ] Token JTI (unique ID) is generated using a cryptographically secure random source
- [ ] RSA signing keys are at least 4096 bits; EdDSA keys use Ed25519
- [ ] Signing keys are loaded from files with restrictive permissions (0640 or stricter)
- [ ] Development/embedded keys are never used in production (check for warning logs)

### 1.4 Token Expiry and Revocation

- [ ] Expired tokens are rejected by the registry (not just the auth service)
- [ ] There is no token refresh mechanism (clients must re-authenticate)
- [ ] Key rotation procedure is documented and tested
- [ ] Old signing keys can be removed after max token TTL has elapsed

---

## 2. Authorization

### 2.1 Role-Based Access Control (RBAC)

- [ ] Roles are well-defined: Admin, Maintainer, Reader
- [ ] Role hierarchy is enforced (Reader cannot push, Maintainer cannot manage)
- [ ] Default role for authenticated users without explicit policy is Reader (pull only)
- [ ] Admin role is granted explicitly, never by default
- [ ] Role assignments are scoped to tenant + project (not global)

### 2.2 Tenant Isolation

- [ ] Each API request is scoped to exactly one tenant
- [ ] Cross-tenant access is impossible regardless of role
- [ ] Tenant ID is derived from the validated token, not from URL path alone
- [ ] Disabled tenants cannot authenticate or access any resources
- [ ] Tenant storage prefixes are unique and non-overlapping
- [ ] Tenant rate limits are enforced independently

### 2.3 Scope Enforcement

- [ ] Token scopes are intersected (not unioned) with requested operations
- [ ] Push operations require explicit `push` scope in the token
- [ ] Delete operations require explicit `delete` scope in the token
- [ ] Repository scopes are validated against the actual request path
- [ ] Wildcard scopes are not supported (each repository is listed explicitly)
- [ ] Scope escalation is prevented (token for repo A cannot access repo B)

---

## 3. Credential Management

### 3.1 No Long-Lived Secrets

- [ ] No static API keys or passwords are used in production
- [ ] Bootstrap admin is disabled after initial setup (or on first OIDC login)
- [ ] CI/CD integrations use OIDC identity tokens, not stored secrets
- [ ] Docker config.json credentials are removed after each CI/CD pipeline run

### 3.2 In-Memory Security

- [ ] Signing keys are loaded into memory and not written to temporary files
- [ ] Token values are not logged at any log level (including debug/trace)
- [ ] Identity tokens from OIDC providers are not persisted to disk
- [ ] Rate limiter state is in-memory only (no external state store with creds)

### 3.3 Key Management

- [ ] Signing key files are owned by the service user, not root
- [ ] Signing key files have permissions 0640 or stricter
- [ ] Keys are not included in container images (mounted at runtime)
- [ ] Key rotation can be performed without downtime (dual-key support)
- [ ] Backup/recovery procedure for signing keys is documented

---

## 4. Network Security

### 4.1 TLS Configuration

- [ ] All external-facing endpoints use TLS 1.2 or later
- [ ] Self-signed certificates are not used in production
- [ ] TLS certificates are rotated before expiry (automated via cert-manager or similar)
- [ ] Internal service-to-service communication uses mTLS or a service mesh
- [ ] HTTP Strict Transport Security (HSTS) headers are set
- [ ] Certificate chain is complete (no missing intermediates)

### 4.2 Rate Limiting

- [ ] Per-tenant rate limiting is enabled and configured appropriately
- [ ] Per-IP rate limiting is enabled for unauthenticated endpoints
- [ ] Token issuance endpoint has a separate, stricter rate limit
- [ ] Rate limit responses include `Retry-After` headers
- [ ] Rate limit counters cannot be bypassed via IP rotation (use tenant-scoped limits)
- [ ] Health and metrics endpoints are excluded from rate limiting (or have high limits)

### 4.3 Network Policies

- [ ] Registry and auth services are not directly exposed to the internet (behind ingress/LB)
- [ ] Metrics endpoint (port 9090) is not exposed externally
- [ ] Kubernetes NetworkPolicies restrict pod-to-pod communication
- [ ] Egress is restricted to known endpoints (OIDC providers, storage backends)

---

## 5. Supply Chain Security

### 5.1 Image Signing and Verification

- [ ] Pushed images can be signed using cosign or Notation
- [ ] Content trust enforcement is configurable per project
- [ ] Image digests (sha256) are used for all internal references, not tags alone
- [ ] Tag immutability is configurable per project

### 5.2 Vulnerability Scanning

- [ ] Images are scanned for known vulnerabilities on push (or via webhook)
- [ ] Base images used in NebulaCR's own Dockerfile are regularly updated
- [ ] Dependency audit is performed on NebulaCR's Cargo.lock (`cargo audit`)
- [ ] SBOM (Software Bill of Materials) generation is supported

### 5.3 Build Provenance

- [ ] CI/CD pipelines generate SLSA provenance attestations
- [ ] Attestations are stored alongside images in the registry
- [ ] Provenance can be verified before deployment

---

## 6. Logging and Audit Trail

### 6.1 Security Event Logging

- [ ] All authentication attempts are logged (success and failure)
- [ ] All authorization decisions are logged with the subject, action, and resource
- [ ] Token issuance events are logged with tenant, project, role, and token JTI
- [ ] Failed requests include the failure reason (but not sensitive data)
- [ ] Administrative actions (tenant creation, role changes) are logged

### 6.2 No Sensitive Data in Logs

- [ ] JWT token values never appear in logs at any level
- [ ] OIDC identity tokens never appear in logs
- [ ] Passwords and password hashes never appear in logs
- [ ] HTTP Authorization headers are redacted in request logs
- [ ] Error messages returned to clients do not leak internal state

### 6.3 Log Integrity and Retention

- [ ] Logs are shipped to a centralized, tamper-evident logging system
- [ ] Log retention meets compliance requirements (90 days minimum recommended)
- [ ] Log access is restricted to authorized personnel
- [ ] Structured JSON logging is enabled (not free-form text)
- [ ] Each log entry includes a correlation/request ID for traceability

### 6.4 Metrics and Alerting

- [ ] Authentication failure rate is monitored and alerted on (brute force detection)
- [ ] Rate limit exhaustion events trigger alerts
- [ ] Token issuance rate is monitored for anomalies
- [ ] Service health checks are monitored externally
- [ ] Storage utilization is monitored per tenant

---

## 7. Container and Runtime Security

### 7.1 Container Hardening

- [ ] Container runs as a non-root user (UID 10001)
- [ ] Container filesystem is read-only where possible
- [ ] No unnecessary packages are installed in the runtime image
- [ ] Container image is based on a minimal base (debian-slim, not full debian)
- [ ] Container image is scanned for vulnerabilities before deployment

### 7.2 Kubernetes Security

- [ ] Pod security standards are enforced (restricted profile)
- [ ] Service accounts use minimal RBAC permissions
- [ ] Secrets are stored in a secrets manager (Vault, AWS Secrets Manager), not K8s Secrets
- [ ] Resource limits (CPU, memory) are set to prevent resource exhaustion
- [ ] Liveness and readiness probes are configured

---

## Audit Schedule

| Frequency   | Scope                                             |
|-------------|---------------------------------------------------|
| Continuous  | Automated: dependency scanning, image scanning    |
| Weekly      | Review authentication failure logs                |
| Monthly     | Review access policies and role assignments       |
| Quarterly   | Full checklist review, penetration testing        |
| Annually    | Third-party security audit, key rotation          |

---

## Sign-Off

| Reviewer        | Date       | Sections Reviewed | Status  |
|-----------------|------------|-------------------|---------|
|                 |            |                   |         |
