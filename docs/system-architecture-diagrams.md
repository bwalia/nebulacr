# NebulaCR System Architecture

> Comprehensive design document covering system topology, authentication flows,
> data models, deployment patterns, security boundaries, and observability.
>
> **Version**: 1.0
> **Last updated**: 2026-03-25
> **Status**: Living document

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Zero-Trust Auth Flow](#2-zero-trust-auth-flow)
3. [Token Issuance Sequence](#3-token-issuance-sequence)
4. [Docker Login + Push Flow](#4-docker-login--push-flow)
5. [Multi-Tenancy Data Model](#5-multi-tenancy-data-model)
6. [Kubernetes Controller Reconciliation Loop](#6-kubernetes-controller-reconciliation-loop)
7. [HA Deployment Topology](#7-ha-deployment-topology)
8. [Network Security and Trust Boundaries](#8-network-security-and-trust-boundaries)
9. [CI/CD Integration Patterns](#9-cicd-integration-patterns)
10. [Observability Stack](#10-observability-stack)
11. [Threat Model Diagram](#11-threat-model-diagram)

---

## 1. System Overview

NebulaCR is a multi-tenant, zero-trust container registry built in Rust.
It consists of two stateless services (`nebula-auth` on port 5001 and
`nebula-registry` on port 5000), a shared library (`nebula-common`), a
Kubernetes controller that manages CRDs, and pluggable object storage.
External dependencies include OIDC identity providers, HashiCorp Vault
(optional, for key management), and a Prometheus/Grafana observability stack.

```
 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │                                   EXTERNAL CLIENTS                                      │
 │                                                                                         │
 │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
 │   │ Docker CLI   │    │ CI Pipeline  │    │   kubectl    │    │  Helm / CD   │          │
 │   │ (push/pull)  │    │ (GH Actions, │    │ (CRD apply)  │    │ (ArgoCD)     │          │
 │   └──────┬───────┘    │  GitLab CI)  │    └──────┬───────┘    └──────┬───────┘          │
 │          │            └──────┬───────┘           │                    │                  │
 └──────────┼───────────────────┼───────────────────┼────────────────────┼──────────────────┘
            │                   │                   │                    │
            │ HTTPS             │ HTTPS             │ HTTPS              │ HTTPS
            ▼                   ▼                   ▼                    ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────────┐
 │                          INGRESS / LOAD BALANCER (L7)                                    │
 │                                                                                          │
 │   TLS termination  ──  Path-based routing  ──  Rate limiting  ──  WAF (optional)         │
 │                                                                                          │
 │   /v2/*        ──────►  nebulacr-registry service                                        │
 │   /auth/*      ──────►  nebulacr-auth service                                            │
 │   /.well-known ──────►  nebulacr-auth service                                            │
 └────────┬───────────────────────┬─────────────────────────────────────────────────────────┘
          │                       │
          ▼                       ▼
 ┌─────────────────────┐  ┌─────────────────────┐     ┌──────────────────────────────────┐
 │                     │  │                     │     │       OIDC PROVIDERS              │
 │   nebula-registry   │  │    nebula-auth      │     │                                  │
 │   :5000             │  │    :5001            │◄───►│  ┌────────────┐ ┌────────────┐   │
 │                     │  │                     │     │  │  GitHub    │ │  Google     │   │
 │  ┌───────────────┐  │  │  ┌───────────────┐  │     │  │  Actions   │ │  Workspace  │   │
 │  │ OCI Dist API  │  │  │  │ OIDC Validator│  │     │  │  OIDC      │ │  OIDC       │   │
 │  │ (V2)          │  │  │  │ (JWKS cache)  │  │     │  └────────────┘ └────────────┘   │
 │  ├───────────────┤  │  │  ├───────────────┤  │     │  ┌────────────┐ ┌────────────┐   │
 │  │ JWT Verifier  │  │  │  │ RBAC Engine   │  │     │  │  Azure AD  │ │  GitLab    │   │
 │  │ (RS256/EdDSA) │  │  │  │ (Policy eval) │  │     │  │  OIDC      │ │  CI OIDC   │   │
 │  ├───────────────┤  │  │  ├───────────────┤  │     │  └────────────┘ └────────────┘   │
 │  │ Tenant Isolat.│  │  │  │ JWT Signer    │  │     └──────────────────────────────────┘
 │  │ (path-prefix) │  │  │  │ (RS256 key)   │  │
 │  ├───────────────┤  │  │  ├───────────────┤  │     ┌──────────────────────────────────┐
 │  │ Rate Limiter  │  │  │  │ Rate Limiter  │  │     │       HASHICORP VAULT            │
 │  │ (per-tenant)  │  │  │  │ (per-tenant   │  │     │       (optional)                 │
 │  └───────────────┘  │  │  │  RPM)         │  │     │                                  │
 │         │           │  │  └───────────────┘  │◄───►│  Transit engine: JWT signing     │
 │         │           │  │                     │     │  KV engine: OIDC client secrets   │
 └─────────┼───────────┘  └─────────────────────┘     │  PKI engine: mTLS certificates   │
           │                                           └──────────────────────────────────┘
           ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────────┐
 │                              OBJECT STORAGE                                              │
 │                                                                                          │
 │   ┌───────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐                      │
 │   │ Filesystem│    │  AWS S3   │    │ GCS       │    │ Azure Blob│                      │
 │   │ (dev/test)│    │ (prod)    │    │ (prod)    │    │ (prod)    │                      │
 │   └───────────┘    └───────────┘    └───────────┘    └───────────┘                      │
 │                                                                                          │
 │   Layout: <tenant>/<project>/<repo>/{blobs,manifests,tags,uploads}/...                   │
 └──────────────────────────────────────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────────────────────────────┐
 │                           KUBERNETES CONTROL PLANE                                       │
 │                                                                                          │
 │   ┌───────────────────┐    ┌────────────────────────────────────────┐                    │
 │   │  K8s API Server   │◄──►│  nebula-controller                    │                    │
 │   │                   │    │  (watches CRDs, reconciles state)     │                    │
 │   └───────────────────┘    └────────────────────────────────────────┘                    │
 │                                                                                          │
 │   CRDs: Tenant (cluster) │ Project (namespaced) │ AccessPolicy │ TokenPolicy             │
 └──────────────────────────────────────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────────────────────────────┐
 │                           OBSERVABILITY STACK                                            │
 │                                                                                          │
 │   ┌────────────┐      ┌────────────┐      ┌────────────┐                                │
 │   │ Prometheus │ ───► │  Grafana   │      │ Jaeger /   │                                │
 │   │ (scrape    │      │ (dashboards│      │ Tempo      │                                │
 │   │  :9090)    │      │  + alerts) │      │ (traces)   │                                │
 │   └────────────┘      └────────────┘      └────────────┘                                │
 └──────────────────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary

| Component           | Type         | Port(s)     | Scaling        | State                           |
|---------------------|------------- |-------------|----------------|---------------------------------|
| nebula-registry     | Deployment   | 5000, 9090  | HPA 2-10       | Stateless (object store)        |
| nebula-auth         | Deployment   | 5001, 9091  | HPA 2-6        | Stateless (in-mem + future DB)  |
| nebula-controller   | Deployment   | 8080        | 1 active (leader) | Watches K8s API              |
| Object Storage      | External     | N/A         | Managed (S3)   | Persistent, cross-AZ           |
| Ingress             | Ingress      | 443         | LB-managed     | Stateless                       |
| Vault               | External     | 8200        | HA cluster     | Persistent (Raft/Consul)        |
| Prometheus          | StatefulSet  | 9090        | 1-2 replicas   | TSDB on PV                      |

---

## 2. Zero-Trust Auth Flow

NebulaCR implements zero-trust authentication: no long-lived secrets are stored
or transmitted. CI/CD systems authenticate using OIDC identity tokens issued by
trusted providers. The auth service validates the identity token cryptographically,
resolves RBAC policies, and issues a short-lived (5-minute default) access JWT.

### Full Sequence: CI Pipeline to Registry Push

```
 ┌──────────┐          ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
 │ CI Runner│          │ GitHub OIDC  │          │ nebula-auth  │          │nebula-registry│
 │ (GH Act.)│          │ Provider     │          │ :5001        │          │ :5000         │
 └────┬─────┘          └──────┬───────┘          └──────┬───────┘          └──────┬───────┘
      │                       │                         │                         │
      │  ── Step 1: Request OIDC ID token ──            │                         │
      │                       │                         │                         │
      │  GET https://token.   │                         │                         │
      │   actions.githubusercontent.com/                │                         │
      │   ?audience=nebulacr  │                         │                         │
      │──────────────────────►│                         │                         │
      │                       │                         │                         │
      │  200 OK               │                         │                         │
      │  {                    │                         │                         │
      │    "value": "<JWT>"   │                         │                         │
      │  }                    │                         │                         │
      │◄──────────────────────│                         │                         │
      │                       │                         │                         │
      │  ┌────────────────────────────────────────┐     │                         │
      │  │ GitHub OIDC JWT Claims:                │     │                         │
      │  │   iss: "https://token.actions.          │     │                         │
      │  │         githubusercontent.com"          │     │                         │
      │  │   sub: "repo:acme/api:ref:refs/        │     │                         │
      │  │         heads/main"                    │     │                         │
      │  │   aud: "nebulacr"                      │     │                         │
      │  │   repository: "acme/api"               │     │                         │
      │  │   repository_owner: "acme"             │     │                         │
      │  │   workflow: "build-and-push"            │     │                         │
      │  │   ref: "refs/heads/main"               │     │                         │
      │  │   sha: "a1b2c3d4..."                   │     │                         │
      │  │   actor: "developer"                   │     │                         │
      │  │   exp: 1711364400                      │     │                         │
      │  └────────────────────────────────────────┘     │                         │
      │                       │                         │                         │
      │  ── Step 2: Exchange OIDC token for registry access token ──             │
      │                       │                         │                         │
      │  POST /auth/token HTTP/1.1                      │                         │
      │  Host: registry.example.com                     │                         │
      │  Content-Type: application/json                 │                         │
      │                                                 │                         │
      │  {                                              │                         │
      │    "identity_token": "<GitHub OIDC JWT>",       │                         │
      │    "scope": {                                   │                         │
      │      "tenant": "acme",                          │                         │
      │      "project": "backend",                      │                         │
      │      "repository": "api",                       │                         │
      │      "actions": ["pull", "push"]                │                         │
      │    }                                            │                         │
      │  }                                              │                         │
      │────────────────────────────────────────────────►│                         │
      │                       │                         │                         │
      │                       │  ── Step 3: Fetch JWKS  │                         │
      │                       │         (cached) ──     │                         │
      │                       │                         │                         │
      │                       │  GET https://token.     │                         │
      │                       │   actions.github        │                         │
      │                       │   usercontent.com/      │                         │
      │                       │   .well-known/          │                         │
      │                       │   openid-configuration  │                         │
      │                       │◄────────────────────────│                         │
      │                       │                         │                         │
      │                       │  200 OK                 │                         │
      │                       │  { "jwks_uri": "..." }  │                         │
      │                       │────────────────────────►│                         │
      │                       │                         │                         │
      │                       │  GET /.well-known/      │                         │
      │                       │      jwks               │                         │
      │                       │◄────────────────────────│                         │
      │                       │                         │                         │
      │                       │  200 OK                 │                         │
      │                       │  { "keys": [{ RSA }] }  │                         │
      │                       │────────────────────────►│                         │
      │                       │                         │                         │
      │                       │     ── Step 4: Auth     │                         │
      │                       │        processing ──    │                         │
      │                       │                         │                         │
      │                       │  ┌──────────────────────────────┐                 │
      │                       │  │ 4a. Verify JWT signature     │                 │
      │                       │  │     (RS256 via JWKS)         │                 │
      │                       │  │ 4b. Validate exp, iss, aud   │                 │
      │                       │  │ 4c. Extract sub claim        │                 │
      │                       │  │ 4d. Resolve tenant "acme"    │                 │
      │                       │  │     → tenant_id (UUID)       │                 │
      │                       │  │ 4e. Check tenant.enabled     │                 │
      │                       │  │ 4f. Resolve project "backend"│                 │
      │                       │  │     → project_id (UUID)      │                 │
      │                       │  │ 4g. Lookup AccessPolicy for  │                 │
      │                       │  │     (sub, tenant, project)   │                 │
      │                       │  │ 4h. Role = Maintainer        │                 │
      │                       │  │ 4i. Intersect requested      │                 │
      │                       │  │     [pull,push] with role    │                 │
      │                       │  │     → [pull,push] allowed    │                 │
      │                       │  │ 4j. Sign access JWT (RS256)  │                 │
      │                       │  └──────────────────────────────┘                 │
      │                       │                         │                         │
      │  200 OK                                         │                         │
      │  {                                              │                         │
      │    "token": "<NebulaCR Access JWT>",            │                         │
      │    "expires_in": 300,                           │                         │
      │    "issued_at": "2026-03-25T12:00:00Z"          │                         │
      │  }                                              │                         │
      │◄────────────────────────────────────────────────│                         │
      │                       │                         │                         │
      │  ┌────────────────────────────────────────┐     │                         │
      │  │ NebulaCR Access JWT Claims:            │     │                         │
      │  │   iss: "nebulacr"                      │     │                         │
      │  │   sub: "repo:acme/api:ref:refs/        │     │                         │
      │  │         heads/main"                    │     │                         │
      │  │   aud: "nebulacr-registry"             │     │                         │
      │  │   exp: 1711360500  (now + 300s)        │     │                         │
      │  │   iat: 1711360200                      │     │                         │
      │  │   jti: "f47ac10b-..."                  │     │                         │
      │  │   tenant_id: "550e8400-..."            │     │                         │
      │  │   project_id: "6ba7b810-..."           │     │                         │
      │  │   role: "maintainer"                   │     │                         │
      │  │   scopes: [{                           │     │                         │
      │  │     repository: "api",                 │     │                         │
      │  │     actions: ["pull", "push"]          │     │                         │
      │  │   }]                                   │     │                         │
      │  └────────────────────────────────────────┘     │                         │
      │                       │                         │                         │
      │  ── Step 5: Push image using access token ──                              │
      │                       │                         │                         │
      │  POST /v2/acme/backend/api/blobs/uploads/ HTTP/1.1                        │
      │  Authorization: Bearer <NebulaCR Access JWT>                              │
      │─────────────────────────────────────────────────────────────────────────►  │
      │                       │                         │                         │
      │                       │                         │   ┌──────────────────┐   │
      │                       │                         │   │ Validate JWT:    │   │
      │                       │                         │   │ - sig (RS256)    │   │
      │                       │                         │   │ - exp, iss, aud  │   │
      │                       │                         │   │ - scope includes │   │
      │                       │                         │   │   "push" on repo │   │
      │                       │                         │   │ - tenant match   │   │
      │                       │                         │   └──────────────────┘   │
      │                       │                         │                         │
      │  202 Accepted                                                             │
      │  Location: /v2/acme/backend/api/blobs/uploads/<uuid>                      │
      │◄──────────────────────────────────────────────────────────────────────────│
      │                       │                         │                         │
```

### Key Security Properties

- **No shared secrets**: CI runners never possess long-lived registry credentials.
- **Short-lived tokens**: Access JWTs expire in 300 seconds (configurable).
- **Scope-bound**: Each token is scoped to a specific tenant/project/repo + actions.
- **Cryptographic chain**: GitHub signs the OIDC JWT; NebulaCR validates it via JWKS
  and issues its own JWT signed with a separate RSA key.
- **Audit trail**: Every token issuance generates an `AuditEvent` with subject, tenant,
  action, decision, reason, request_id, and source_ip.

---

## 3. Token Issuance Sequence

This section details the internal processing steps of `POST /auth/token` and
the Docker-compatible `GET /auth/token` endpoint.

```
                            ┌─────────────────────────────────────────────┐
                            │          nebula-auth :5001                  │
                            │                                             │
  Incoming Request          │                                             │
 ───────────────────────►   │  ┌─────────────────────────────────────┐    │
                            │  │  1. RATE LIMIT CHECK                │    │
                            │  │     Key: tenant name                │    │
                            │  │     Limit: token_issue_rpm (60/min) │    │
                            │  │     Result: PASS / 429 Too Many     │    │
                            │  └──────────────┬──────────────────────┘    │
                            │                 │                           │
                            │                 ▼                           │
                            │  ┌─────────────────────────────────────┐    │
                            │  │  2. OIDC TOKEN VALIDATION           │    │
                            │  │                                     │    │
                            │  │  a. Split JWT into header.payload.  │    │
                            │  │     signature (3 parts)             │    │
                            │  │  b. Base64url-decode header         │    │
                            │  │     → extract "kid", "alg"          │    │
                            │  │  c. Fetch OIDC discovery document   │    │
                            │  │     GET {issuer}/.well-known/       │    │
                            │  │         openid-configuration        │    │
                            │  │     (cached with TTL)               │    │
                            │  │  d. Fetch JWKS from jwks_uri        │    │
                            │  │     GET {jwks_uri}                  │    │
                            │  │     (cached with TTL)               │    │
                            │  │  e. Find key by "kid" in JWKS       │    │
                            │  │  f. Verify RS256/EdDSA signature    │    │
                            │  │  g. Validate claims:                │    │
                            │  │     - exp > now (not expired)       │    │
                            │  │     - iss matches provider config   │    │
                            │  │     - aud matches client_id         │    │
                            │  │     - sub is non-empty              │    │
                            │  │  h. Extract subject from "sub"      │    │
                            │  │     claim (or configured claim)     │    │
                            │  │                                     │    │
                            │  │  FAIL → 401 Unauthorized            │    │
                            │  └──────────────┬──────────────────────┘    │
                            │                 │                           │
                            │                 ▼                           │
                            │  ┌─────────────────────────────────────┐    │
                            │  │  3. TENANT RESOLUTION               │    │
                            │  │                                     │    │
                            │  │  a. Lookup tenant by name           │    │
                            │  │     Key: request.scope.tenant       │    │
                            │  │  b. Verify tenant.enabled == true   │    │
                            │  │  c. Extract tenant_id (UUID)        │    │
                            │  │                                     │    │
                            │  │  FAIL → 404 TenantNotFound          │    │
                            │  │         403 Forbidden (disabled)    │    │
                            │  └──────────────┬──────────────────────┘    │
                            │                 │                           │
                            │                 ▼                           │
                            │  ┌─────────────────────────────────────┐    │
                            │  │  4. PROJECT RESOLUTION              │    │
                            │  │                                     │    │
                            │  │  a. Lookup project by (tenant_id,   │    │
                            │  │     project_name)                   │    │
                            │  │  b. Extract project_id (UUID)       │    │
                            │  │                                     │    │
                            │  │  FAIL → 404 ProjectNotFound         │    │
                            │  └──────────────┬──────────────────────┘    │
                            │                 │                           │
                            │                 ▼                           │
                            │  ┌─────────────────────────────────────┐    │
                            │  │  5. RBAC EVALUATION                 │    │
                            │  │                                     │    │
                            │  │  a. Query AccessPolicy entries      │    │
                            │  │     matching (subject, tenant_id)   │    │
                            │  │  b. Project-scoped policy takes     │    │
                            │  │     precedence over tenant-wide     │    │
                            │  │  c. Determine role:                 │    │
                            │  │     Admin > Maintainer > Reader     │    │
                            │  │  d. Default: Reader (if authed but  │    │
                            │  │     no explicit policy)             │    │
                            │  │  e. Intersect requested actions     │    │
                            │  │     with role.allowed_actions()     │    │
                            │  │                                     │    │
                            │  │  Role permissions:                  │    │
                            │  │  ┌───────────┬─────────────────────┐│    │
                            │  │  │ Admin     │ pull push delete    ││    │
                            │  │  │           │ tag manage          ││    │
                            │  │  ├───────────┼─────────────────────┤│    │
                            │  │  │ Maintainer│ pull push delete tag││    │
                            │  │  ├───────────┼─────────────────────┤│    │
                            │  │  │ Reader    │ pull                ││    │
                            │  │  └───────────┴─────────────────────┘│    │
                            │  │                                     │    │
                            │  │  FAIL → 403 Forbidden               │    │
                            │  │    (no actions permitted)           │    │
                            │  └──────────────┬──────────────────────┘    │
                            │                 │                           │
                            │                 ▼                           │
                            │  ┌─────────────────────────────────────┐    │
                            │  │  6. JWT SIGNING                     │    │
                            │  │                                     │    │
                            │  │  Build TokenClaims:                 │    │
                            │  │    iss: "nebulacr"                  │    │
                            │  │    sub: <authenticated subject>     │    │
                            │  │    aud: "nebulacr-registry"         │    │
                            │  │    exp: now + token_ttl_seconds     │    │
                            │  │    iat: now                         │    │
                            │  │    jti: UUID v4 (unique token ID)   │    │
                            │  │    tenant_id: <resolved UUID>       │    │
                            │  │    project_id: <resolved UUID>      │    │
                            │  │    role: <resolved role>            │    │
                            │  │    scopes: [{repo, [actions]}]      │    │
                            │  │                                     │    │
                            │  │  Sign with:                         │    │
                            │  │    - Local RSA key (RS256)          │    │
                            │  │    OR                               │    │
                            │  │    - Vault Transit engine (future)  │    │
                            │  │                                     │    │
                            │  │  FAIL → 500 Internal Error          │    │
                            │  └──────────────┬──────────────────────┘    │
                            │                 │                           │
                            │                 ▼                           │
                            │  ┌─────────────────────────────────────┐    │
  ◄──────────────────────   │  │  7. RESPONSE                       │    │
  200 OK                    │  │                                     │    │
  {                         │  │  { "token": "<signed JWT>",         │    │
    token, expires_in,      │  │    "expires_in": 300,               │    │
    issued_at               │  │    "issued_at": "2026-03-25T..." }  │    │
  }                         │  │                                     │    │
                            │  │  Metrics: registry_token_issued_total│    │
                            │  │  Log: "token issued" + context      │    │
                            │  └─────────────────────────────────────┘    │
                            └─────────────────────────────────────────────┘
```

---

## 4. Docker Login + Push Flow

Standard Docker clients use the [Token Authentication Specification](https://docs.docker.com/registry/spec/auth/token/).
NebulaCR implements both the challenge-response handshake (401 → token fetch → retry)
and the OCI Distribution blob/manifest upload protocol.

### 4.1 Docker Login and Pull

```
 ┌──────────┐                 ┌──────────────┐                 ┌──────────────┐
 │  Docker  │                 │nebula-registry│                 │ nebula-auth  │
 │  Client  │                 │ :5000         │                 │ :5001        │
 └────┬─────┘                 └──────┬───────┘                 └──────┬───────┘
      │                              │                                │
      │  1. GET /v2/ HTTP/1.1        │                                │
      │─────────────────────────────►│                                │
      │                              │                                │
      │  2. 401 Unauthorized         │                                │
      │     WWW-Authenticate:        │                                │
      │       Bearer realm=          │                                │
      │       "https://registry.     │                                │
      │        example.com/          │                                │
      │        auth/token",          │                                │
      │       service=               │                                │
      │       "nebulacr-registry",   │                                │
      │       scope=                 │                                │
      │       "repository:acme/      │                                │
      │        backend/api:pull"     │                                │
      │◄─────────────────────────────│                                │
      │                              │                                │
      │  3. GET /auth/token                                           │
      │     ?service=nebulacr-registry                                │
      │     &scope=repository:acme/backend/api:pull                   │
      │     Authorization: Basic base64("admin:admin")                │
      │──────────────────────────────────────────────────────────────►│
      │                              │                                │
      │                              │           ┌────────────────────┤
      │                              │           │ Parse scope string │
      │                              │           │ Authenticate Basic │
      │                              │           │ Resolve tenant     │
      │                              │           │ Resolve role       │
      │                              │           │ Sign JWT           │
      │                              │           └────────────────────┤
      │                              │                                │
      │  4. 200 OK                                                    │
      │     {                                                         │
      │       "token": "<JWT>",                                       │
      │       "access_token": "<JWT>",                                │
      │       "expires_in": 300,                                      │
      │       "issued_at": "2026-03-25T12:00:00+00:00"                │
      │     }                                                         │
      │◄──────────────────────────────────────────────────────────────│
      │                              │                                │
      │  5. GET /v2/acme/backend/    │                                │
      │     api/manifests/v1.0.0     │                                │
      │     Authorization:           │                                │
      │       Bearer <JWT>           │                                │
      │─────────────────────────────►│                                │
      │                              │                                │
      │              ┌───────────────┤                                │
      │              │ Decode JWT    │                                │
      │              │ Verify sig    │                                │
      │              │ Check exp     │                                │
      │              │ Validate iss  │                                │
      │              │ Validate aud  │                                │
      │              │ Check scope:  │                                │
      │              │  "pull" on    │                                │
      │              │  "api" repo   │                                │
      │              │ Read manifest │                                │
      │              │  from storage │                                │
      │              └───────────────┤                                │
      │                              │                                │
      │  6. 200 OK                   │                                │
      │     Content-Type:            │                                │
      │       application/vnd.oci.   │                                │
      │       image.manifest.v2+json │                                │
      │     Docker-Content-Digest:   │                                │
      │       sha256:abc123...       │                                │
      │     <manifest JSON body>     │                                │
      │◄─────────────────────────────│                                │
      │                              │                                │
```

### 4.2 Docker Push (Blob Upload + Manifest)

```
 ┌──────────┐                 ┌──────────────┐
 │  Docker  │                 │nebula-registry│
 │  Client  │                 │ :5000         │
 └────┬─────┘                 └──────┬───────┘
      │                              │
      │  ── (auth handshake as above, requesting scope "push") ──
      │                              │
      │  ── Blob upload (monolithic or chunked) ──
      │                              │
      │  1. POST /v2/acme/backend/   │
      │     api/blobs/uploads/       │
      │     Authorization: Bearer <JWT>
      │─────────────────────────────►│
      │                              │
      │  2. 202 Accepted             │
      │     Location: /v2/acme/      │
      │       backend/api/blobs/     │
      │       uploads/<uuid>         │
      │     Docker-Upload-UUID:      │
      │       <uuid>                 │
      │◄─────────────────────────────│
      │                              │
      │  3. PATCH /v2/acme/backend/  │       ← (optional: chunked upload)
      │     api/blobs/uploads/<uuid> │
      │     Content-Range: 0-1048575 │
      │     Content-Type:            │
      │       application/           │
      │       octet-stream           │
      │     <layer data chunk>       │
      │─────────────────────────────►│
      │                              │
      │  4. 202 Accepted             │
      │     Range: 0-1048575         │
      │◄─────────────────────────────│
      │                              │
      │  5. PUT /v2/acme/backend/    │       ← complete upload
      │     api/blobs/uploads/<uuid> │
      │     ?digest=sha256:abc123    │
      │     <final chunk or empty>   │
      │─────────────────────────────►│
      │                              │
      │          ┌───────────────────┤
      │          │ Verify digest     │
      │          │ Move to:          │
      │          │  acme/backend/api/│
      │          │   blobs/sha256/   │
      │          │   abc123          │
      │          └───────────────────┤
      │                              │
      │  6. 201 Created              │
      │     Docker-Content-Digest:   │
      │       sha256:abc123          │
      │     Location: /v2/acme/      │
      │       backend/api/blobs/     │
      │       sha256:abc123          │
      │◄─────────────────────────────│
      │                              │
      │  ── (repeat for each layer blob) ──
      │                              │
      │  ── Manifest upload ──       │
      │                              │
      │  7. PUT /v2/acme/backend/    │
      │     api/manifests/v1.0.0     │
      │     Content-Type:            │
      │       application/vnd.oci.   │
      │       image.manifest.v2+json │
      │     <manifest JSON>          │
      │─────────────────────────────►│
      │                              │
      │          ┌───────────────────┤
      │          │ Parse manifest    │
      │          │ Verify all blobs  │
      │          │   referenced      │
      │          │   exist in store  │
      │          │ Compute digest    │
      │          │ Write manifest    │
      │          │ Write tag link:   │
      │          │   tags/v1.0.0 →   │
      │          │   sha256:<digest> │
      │          └───────────────────┤
      │                              │
      │  8. 201 Created              │
      │     Docker-Content-Digest:   │
      │       sha256:def456          │
      │     Location: /v2/acme/      │
      │       backend/api/manifests/ │
      │       sha256:def456          │
      │◄─────────────────────────────│
      │                              │
```

### Storage Operations During Push

```
  Object Store Write Operations
  ─────────────────────────────

  1. Upload session created:
     acme/backend/api/uploads/<uuid>

  2. Blob finalized (content-addressed):
     acme/backend/api/blobs/sha256/<hex-digest>

  3. Manifest stored by digest:
     acme/backend/api/manifests/sha256:<hex-digest>

  4. Tag symlink written:
     acme/backend/api/tags/v1.0.0
     Content: "sha256:<hex-digest>"

  5. Upload session cleaned up:
     acme/backend/api/uploads/<uuid>  (deleted)
```

---

## 5. Multi-Tenancy Data Model

### 5.1 Entity-Relationship Diagram

```
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                                                                              │
  │  ┌─────────────────────────┐         ┌─────────────────────────┐             │
  │  │        TENANT           │         │      TOKEN POLICY       │             │
  │  │  (Cluster-scoped CRD)   │         │  (Namespaced CRD)       │             │
  │  ├─────────────────────────┤         ├─────────────────────────┤             │
  │  │ id: UUID [PK]           │◄────────│ tenantRef: string [FK]  │             │
  │  │ name: string [unique]   │    1:N  │ maxTokenLifetime: dur   │             │
  │  │ display_name: string    │         │ maxRefreshLifetime: dur │             │
  │  │ enabled: bool           │         │ allowedScopes: [string] │             │
  │  │ storage_prefix: string  │         │ maxConcurrentSessions   │             │
  │  │ rate_limit_rps: u32     │         │ rotation: {enabled,     │             │
  │  │ admin_email: string     │         │   interval, grace}      │             │
  │  │ oidc_subject: string    │         │ revocation: {on_pass,   │             │
  │  │ quotas: {storage,       │         │   on_suspend, on_policy}│             │
  │  │   max_repos, max_tags,  │         │ ipRestrictions: {bind,  │             │
  │  │   pull_rate, push_rate} │         │   allowedCidrs}         │             │
  │  │ allowed_ip_cidrs: []    │         │ robotAccounts: {enabled,│             │
  │  │ created_at: timestamp   │         │   maxPerProject, ttl}   │             │
  │  │ updated_at: timestamp   │         └─────────────────────────┘             │
  │  │ status.phase:           │                                                 │
  │  │   Pending|Active|       │                                                 │
  │  │   Suspended|Deleting    │                                                 │
  │  └──────────┬──────────────┘                                                 │
  │             │                                                                │
  │             │ 1:N                                                             │
  │             ▼                                                                │
  │  ┌─────────────────────────┐         ┌─────────────────────────┐             │
  │  │       PROJECT           │         │     ACCESS POLICY       │             │
  │  │  (Namespaced CRD)       │         │  (Namespaced CRD)       │             │
  │  ├─────────────────────────┤         ├─────────────────────────┤             │
  │  │ id: UUID [PK]           │         │ id: UUID [PK]           │             │
  │  │ tenant_id: UUID [FK]    │◄────────│ tenantRef: string [FK]  │             │
  │  │ tenantRef: string       │    1:N  │ subjects: [{kind, name, │             │
  │  │ name: string [unique    │         │   oidcClaim, value}]    │             │
  │  │   within tenant]        │         │ resources: [{type,      │             │
  │  │ display_name: string    │         │   namePattern,          │             │
  │  │ visibility: enum        │         │   projectRef}]          │             │
  │  │   private|internal|     │         │ actions: [pull|push|    │             │
  │  │   public                │         │   delete|list|admin|*]  │             │
  │  │ immutable_tags: bool    │         │ effect: Allow|Deny      │             │
  │  │ vuln_scanning: {        │         │ priority: i32           │             │
  │  │   enabled, block_crit,  │         │ conditions: [{type,     │             │
  │  │   block_high}           │         │   sourceCidrs,          │             │
  │  │ retention: {enabled,    │         │   timeWindowStart/End}] │             │
  │  │   max_age, keep_n,      │         │ status.valid: bool      │             │
  │  │   keep_semver}          │         │ status.matchCount: i64  │             │
  │  │ quotas: {max_repos,     │         └─────────────────────────┘             │
  │  │   max_tags, storage}    │                                                 │
  │  │ status.phase            │                                                 │
  │  └──────────┬──────────────┘                                                 │
  │             │                                                                │
  │             │ 1:N                                                             │
  │             ▼                                                                │
  │  ┌─────────────────────────┐                                                 │
  │  │      REPOSITORY         │                                                 │
  │  │  (Runtime entity)       │                                                 │
  │  ├─────────────────────────┤                                                 │
  │  │ id: UUID [PK]           │                                                 │
  │  │ project_id: UUID [FK]   │                                                 │
  │  │ tenant_id: UUID [FK]    │                                                 │
  │  │ name: string [unique    │                                                 │
  │  │   within project]       │                                                 │
  │  │ created_at: timestamp   │                                                 │
  │  │ updated_at: timestamp   │                                                 │
  │  └──────────┬──────────────┘                                                 │
  │             │                                                                │
  │             │ 1:N                          1:N                                │
  │             ├──────────────────────────────────────────┐                      │
  │             ▼                                          ▼                      │
  │  ┌─────────────────────────┐         ┌─────────────────────────┐             │
  │  │       MANIFEST          │         │         BLOB            │             │
  │  │  (OCI content)          │         │  (OCI content)          │             │
  │  ├─────────────────────────┤         ├─────────────────────────┤             │
  │  │ schema_version: u32     │         │ media_type: string      │             │
  │  │ media_type: string      │         │ digest: string          │             │
  │  │ config: Descriptor      │────────►│   "sha256:<hex>"        │             │
  │  │ layers: [Descriptor]    │  refs   │ size: u64               │             │
  │  └──────────┬──────────────┘         └─────────────────────────┘             │
  │             │                                                                │
  │             │ N:N (via tag links)                                             │
  │             ▼                                                                │
  │  ┌─────────────────────────┐                                                 │
  │  │         TAG             │                                                 │
  │  │  (Pointer file)         │                                                 │
  │  ├─────────────────────────┤                                                 │
  │  │ name: string            │                                                 │
  │  │   e.g. "v1.0.0",       │                                                 │
  │  │   "latest"              │                                                 │
  │  │ target: digest string   │                                                 │
  │  │   → manifest digest     │                                                 │
  │  └─────────────────────────┘                                                 │
  │                                                                              │
  └──────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Storage Path Layout

```
  <storage_root>/
  │
  ├── acme/                                    ◄── Tenant: "acme"
  │   ├── backend/                             ◄── Project: "backend"
  │   │   ├── api-server/                      ◄── Repository: "api-server"
  │   │   │   ├── blobs/
  │   │   │   │   └── sha256/
  │   │   │   │       ├── a1b2c3d4e5f6...      ◄── Layer blob (content-addressed)
  │   │   │   │       ├── b2c3d4e5f6a7...      ◄── Config blob
  │   │   │   │       └── c3d4e5f6a7b8...      ◄── Another layer
  │   │   │   ├── manifests/
  │   │   │   │   ├── sha256:d4e5f6a7b8...     ◄── Manifest by digest
  │   │   │   │   └── sha256:e5f6a7b8c9...     ◄── Another manifest version
  │   │   │   ├── tags/
  │   │   │   │   ├── latest                   ◄── Contains "sha256:d4e5f6a7b8..."
  │   │   │   │   ├── v1.0.0                   ◄── Contains "sha256:d4e5f6a7b8..."
  │   │   │   │   └── v1.1.0                   ◄── Contains "sha256:e5f6a7b8c9..."
  │   │   │   └── uploads/
  │   │   │       └── f47ac10b-58cc-...         ◄── In-progress upload session
  │   │   │
  │   │   └── web-frontend/                    ◄── Another repository
  │   │       ├── blobs/...
  │   │       ├── manifests/...
  │   │       └── tags/...
  │   │
  │   └── infra/                               ◄── Project: "infra"
  │       └── terraform-runner/
  │           └── ...
  │
  ├── globex/                                  ◄── Tenant: "globex" (isolated)
  │   └── platform/
  │       └── ...
  │
  └── ...
```

### 5.3 Isolation Properties

```
  Isolation Dimension     How It Works
  ─────────────────────   ──────────────────────────────────────────────────────
  Storage                 Tenant name is the root path prefix. Storage paths
                          are constructed by nebula-common::storage functions
                          that require explicit (tenant, project, repo) params.
                          A bug in one tenant's query cannot traverse to
                          another tenant's path because the prefix differs.

  Authentication          JWTs contain tenant_id. The registry verifies that
                          the token's tenant_id matches the request path.

  Authorization           AccessPolicy entries are scoped to a tenant_id.
                          RBAC evaluation filters policies by tenant first.

  Rate Limiting           Per-tenant rate limiters (keyed by tenant name)
                          prevent one tenant from exhausting shared resources.

  Quotas                  Tenant CRD defines quotas: storageBytes,
                          maxRepositories, maxTagsPerRepository, pull/push
                          rate limits.

  Network                 Tenant CRD supports allowedIpCidrs for IP-based
                          access restrictions per tenant.

  Metrics                 All metrics are labeled with tenant_id for
                          per-tenant dashboards and alerting.
```

---

## 6. Kubernetes Controller Reconciliation Loop

The nebula-controller watches four CRDs (`Tenant`, `Project`, `AccessPolicy`,
`TokenPolicy`) and reconciles their desired state into the auth/registry services.

### 6.1 Controller Architecture

```
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │                        nebula-controller                                     │
 │                                                                              │
 │  ┌────────────────────────────────────────────────────────────────────────┐  │
 │  │                     Controller Manager                                 │  │
 │  │  (leader election: only 1 active replica at a time)                    │  │
 │  └────────────────────────────────────────────────────────────────────────┘  │
 │                                                                              │
 │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐    │
 │  │ Tenant        │ │ Project       │ │ AccessPolicy  │ │ TokenPolicy   │    │
 │  │ Reconciler    │ │ Reconciler    │ │ Reconciler    │ │ Reconciler    │    │
 │  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘ └───────┬───────┘    │
 │          │                 │                 │                 │             │
 │          ▼                 ▼                 ▼                 ▼             │
 │  ┌────────────────────────────────────────────────────────────────────────┐  │
 │  │                      Work Queue (rate-limited)                         │  │
 │  │  - Deduplication of events for the same object                         │  │
 │  │  - Exponential backoff on failures (1s → 2s → 4s → ... → 5min cap)    │  │
 │  │  - Max requeue attempts before entering degraded state                 │  │
 │  └────────────────────────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Tenant Reconciliation Loop

```
  K8s API Server                        nebula-controller                nebula-auth
  ──────────────                        ─────────────────                ───────────
       │                                       │                              │
       │  Watch event: Tenant "acme"           │                              │
       │  (ADDED / MODIFIED / DELETED)         │                              │
       │──────────────────────────────────────►│                              │
       │                                       │                              │
       │                          ┌────────────┤                              │
       │                          │ Reconcile: │                              │
       │                          │            │                              │
       │                          │ 1. Fetch current Tenant CR                │
       │                          │    spec + status                          │
       │                          │                                           │
       │                          │ 2. Validate spec:                         │
       │                          │    - displayName non-empty                │
       │                          │    - adminEmail valid                     │
       │                          │    - quotas non-negative                  │
       │                          │                                           │
       │                          │ 3. If new (status.phase == ""):           │
       │                          │    a. Create storage prefix dir           │
       │                          │    b. Sync tenant to auth service ───────►│
       │                          │    c. Set status.phase = "Active"         │ Upsert
       │                          │                                           │ tenant
       │                          │ 4. If modified:                           │ in
       │                          │    a. Diff spec vs observed               │ memory
       │                          │    b. Update storage quotas               │
       │                          │    c. Sync to auth service ──────────────►│
       │                          │    d. Update status fields                │
       │                          │                                           │
       │                          │ 5. If spec.enabled == false:              │
       │                          │    a. Set status.phase = "Suspended"      │
       │                          │    b. Notify auth to reject tokens ──────►│
       │                          │                                           │
       │                          │ 6. If deleted (finalizer):                │
       │                          │    a. Set status.phase = "Deleting"       │
       │                          │    b. Garbage-collect storage             │
       │                          │    c. Remove from auth service ──────────►│
       │                          │    d. Remove finalizer                    │
       │                          │                                           │
       │                          │ 7. Update status:                         │
       │                          │    - observedGeneration                   │
       │                          │    - lastReconcileTime                    │
       │                          │    - repositoryCount                      │
       │                          │    - storageUsedBytes                     │
       │                          │    - conditions                           │
       │                          └────────────┤                              │
       │                                       │                              │
       │  Update Tenant status subresource     │                              │
       │◄──────────────────────────────────────│                              │
       │                                       │                              │

  Error Handling:
  ───────────────
  On reconcile failure:
    1. Log error with tenant name, generation, and cause
    2. Set condition: type=Ready, status=False, reason=<error>
    3. Requeue with exponential backoff:
       attempt 1: 1s,  attempt 2: 2s,  attempt 3: 4s, ...
       cap: 5 minutes
    4. After 10 consecutive failures, set status.phase = "Degraded"
    5. Emit Kubernetes Event (type=Warning) on the Tenant object
```

### 6.3 CRD Dependency Graph

```
  ┌──────────────┐
  │    Tenant    │ ◄──── Cluster-scoped
  │  (nebulacr.io│       Must exist before Projects
  │   /v1alpha1) │
  └──────┬───────┘
         │
         │  owns (via tenantRef)
         │
    ┌────┴────┬──────────────────────┐
    │         │                      │
    ▼         ▼                      ▼
 ┌────────┐ ┌──────────────┐  ┌─────────────┐
 │Project │ │ AccessPolicy │  │ TokenPolicy │
 │        │ │              │  │             │
 └────────┘ └──────────────┘  └─────────────┘
    │
    │  owns (via projectRef in AccessPolicy resources)
    ▼
 AccessPolicy can optionally scope to a Project
```

---

## 7. HA Deployment Topology

### 7.1 Production Multi-AZ Layout

```
 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │                              REGION: us-east-1                                           │
 │                                                                                         │
 │   ┌─────────────────────────────────────────────────────────────────────────────────┐   │
 │   │                        Global Load Balancer                                      │   │
 │   │                  (AWS ALB / GCP GCLB / Azure Front Door)                         │   │
 │   │                  DNS: registry.example.com                                       │   │
 │   │                  TLS: cert-manager / ACM                                         │   │
 │   └────────────────────────────┬────────────────────────────────────────────────────┘   │
 │                                │                                                        │
 │              ┌─────────────────┼─────────────────┐                                      │
 │              │                 │                 │                                      │
 │    ┌─────────▼──────┐ ┌───────▼────────┐ ┌─────▼──────────┐                            │
 │    │   AZ: us-e-1a  │ │  AZ: us-e-1b   │ │  AZ: us-e-1c   │                            │
 │    │                │ │                │ │                │                            │
 │    │ ┌────────────┐ │ │ ┌────────────┐ │ │ ┌────────────┐ │                            │
 │    │ │registry-0  │ │ │ │registry-1  │ │ │ │registry-2  │ │                            │
 │    │ │ (Deployment│ │ │ │ (Deployment│ │ │ │ (Deployment│ │                            │
 │    │ │  replica)  │ │ │ │  replica)  │ │ │ │  replica)  │ │                            │
 │    │ └────────────┘ │ │ └────────────┘ │ │ └────────────┘ │                            │
 │    │                │ │                │ │                │                            │
 │    │ ┌────────────┐ │ │ ┌────────────┐ │ │ ┌────────────┐ │                            │
 │    │ │ auth-0     │ │ │ │ auth-1     │ │ │ │ auth-2     │ │                            │
 │    │ │ (Deployment│ │ │ │ (Deployment│ │ │ │ (Deployment│ │                            │
 │    │ │  replica)  │ │ │ │  replica)  │ │ │ │  replica)  │ │                            │
 │    │ └────────────┘ │ │ └────────────┘ │ │ └────────────┘ │                            │
 │    │                │ │                │ │                │                            │
 │    │ ┌────────────┐ │ │                │ │                │                            │
 │    │ │controller  │ │ │ (controller   │ │ (controller   │                            │
 │    │ │ (leader)   │ │ │  standby)     │ │  standby)     │                            │
 │    │ └────────────┘ │ │                │ │                │                            │
 │    └────────────────┘ └────────────────┘ └────────────────┘                            │
 │                                                                                         │
 │    ┌────────────────────────────────────────────────────────────────────────────────┐   │
 │    │                        Object Storage (S3)                                      │   │
 │    │                  Cross-AZ replication (automatic)                                │   │
 │    │                  Versioning enabled                                              │   │
 │    │                  SSE-S3 or SSE-KMS encryption at rest                            │   │
 │    └────────────────────────────────────────────────────────────────────────────────┘   │
 │                                                                                         │
 │    ┌──────────────────────────────┐    ┌──────────────────────────────┐                 │
 │    │  HashiCorp Vault (HA)       │    │  PostgreSQL (future)         │                 │
 │    │  3-node Raft cluster         │    │  Primary + read replica      │                 │
 │    │  Auto-unseal via KMS         │    │  For tenant/policy state     │                 │
 │    └──────────────────────────────┘    └──────────────────────────────┘                 │
 └─────────────────────────────────────────────────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │                          REGION: eu-west-1 (DR / read replica)                           │
 │                                                                                         │
 │    ┌────────────────┐  ┌────────────────┐                                               │
 │    │ registry-0     │  │ auth-0         │                                               │
 │    │ (read-only     │  │ (token         │                                               │
 │    │  replica)      │  │  validation    │                                               │
 │    └────────────────┘  │  only)         │                                               │
 │                         └────────────────┘                                               │
 │                                                                                         │
 │    Object Storage: S3 cross-region replication from us-east-1                            │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Deployment Decisions

| Component         | Kind         | Reason                                                           |
|-------------------|------------- |------------------------------------------------------------------|
| nebula-registry   | Deployment   | Stateless. No local data. All state in object store.             |
| nebula-auth       | Deployment   | Stateless. Signing key mounted from Secret/Vault.                |
| nebula-controller | Deployment   | Single active via leader election. No persistent local state.    |
| Vault             | StatefulSet  | Raft consensus requires stable network identities and storage.   |
| PostgreSQL        | StatefulSet  | Requires persistent volumes and stable pod identities.           |
| Prometheus        | StatefulSet  | TSDB on persistent volume. Stable identity for scrape targets.   |

### 7.3 Token Validation Without Central Bottleneck

```
  Registry replicas validate JWTs locally — no call to the auth service required.

  ┌──────────────┐    JWT in Authorization header    ┌──────────────┐
  │   Client     │──────────────────────────────────►│registry-N    │
  └──────────────┘                                   │              │
                                                     │ 1. Decode JWT│
                                                     │ 2. Verify    │
                                                     │    signature │
                                                     │    using     │
                                                     │    PUBLIC key│
                                                     │    (mounted  │
                                                     │    from      │
                                                     │    Secret)   │
                                                     │ 3. Check exp │
                                                     │ 4. Check iss │
                                                     │ 5. Check aud │
                                                     │ 6. Check     │
                                                     │    scopes    │
                                                     │              │
                                                     │ No network   │
                                                     │ call needed  │
                                                     └──────────────┘

  Key distribution:
  ─────────────────
  - RSA public key is stored in a Kubernetes Secret
  - Mounted into all registry pods as a read-only volume
  - Key rotation: update Secret → rolling restart of registry pods
  - Vault integration (future): Vault Transit engine signs tokens;
    registry fetches public key from auth service's JWKS endpoint
    GET /auth/.well-known/jwks.json (cached with TTL)
```

---

## 8. Network Security and Trust Boundaries

### 8.1 Trust Boundary Diagram

```
 ┌──────────────────────────────────────────────────────────────────────────────────────────┐
 │                              UNTRUSTED ZONE                                              │
 │                          (Public Internet)                                               │
 │                                                                                         │
 │    ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                              │
 │    │ Docker   │  │ CI/CD    │  │ Attacker │  │ Scanner  │                              │
 │    │ Client   │  │ Runner   │  │          │  │          │                              │
 │    └─────┬────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘                              │
 │          │            │             │             │                                     │
 └──────────┼────────────┼─────────────┼─────────────┼─────────────────────────────────────┘
            │            │             │             │
            │ HTTPS/TLS  │ HTTPS/TLS   │ HTTPS/TLS   │ HTTPS/TLS
            │            │             │             │
 ═══════════╪════════════╪═════════════╪═════════════╪══════════ TLS TERMINATION POINT ═════
            │            │             │             │
 ┌──────────┼────────────┼─────────────┼─────────────┼─────────────────────────────────────┐
 │          ▼            ▼             ▼             ▼                                     │
 │   ┌──────────────────────────────────────────────────────┐                              │
 │   │              INGRESS CONTROLLER                       │    DMZ / EDGE ZONE           │
 │   │                                                       │                              │
 │   │  - TLS termination (Let's Encrypt / ACM cert)         │                              │
 │   │  - WAF rules (OWASP Core Rule Set)                    │                              │
 │   │  - IP rate limiting (per source IP)                   │                              │
 │   │  - Request size limits (proxy-body-size)              │                              │
 │   │  - Path-based routing (/v2/* → registry, /auth/* →    │                              │
 │   │    auth)                                              │                              │
 │   │  - Connection timeouts (read: 600s for large pushes)  │                              │
 │   └─────────────────────┬────────────────────────────────┘                              │
 │                         │                                                                │
 ║═════════════════════════╪═══════════════════════ CLUSTER NETWORK BOUNDARY ═══════════════║
 │                         │                                                                │
 │   ┌─────────────────────┼─────────────────────────────────────────────────────────────┐  │
 │   │                     │               TRUSTED ZONE                                   │  │
 │   │                     │          (Kubernetes cluster network)                         │  │
 │   │                     │                                                               │  │
 │   │    ┌────────────────┴─────────────────────────────────────────────────────────┐    │  │
 │   │    │                    Service Mesh / Network Policy Layer                    │    │  │
 │   │    │                                                                          │    │  │
 │   │    │   NetworkPolicy rules:                                                   │    │  │
 │   │    │   ┌──────────────────────────────────────────────────────────────────┐    │    │  │
 │   │    │   │ registry pods:                                                  │    │    │  │
 │   │    │   │   ingress: allow from Ingress controller only (:5000)           │    │    │  │
 │   │    │   │   egress:  allow to object storage, auth service, DNS           │    │    │  │
 │   │    │   │                                                                 │    │    │  │
 │   │    │   │ auth pods:                                                      │    │    │  │
 │   │    │   │   ingress: allow from Ingress controller only (:5001)           │    │    │  │
 │   │    │   │   egress:  allow to OIDC providers (HTTPS), Vault, DNS          │    │    │  │
 │   │    │   │                                                                 │    │    │  │
 │   │    │   │ controller pods:                                                │    │    │  │
 │   │    │   │   ingress: allow from K8s API server (webhooks)                 │    │    │  │
 │   │    │   │   egress:  allow to K8s API server, auth service                │    │    │  │
 │   │    │   │                                                                 │    │    │  │
 │   │    │   │ metrics ports (9090/9091):                                      │    │    │  │
 │   │    │   │   ingress: allow from Prometheus only                           │    │    │  │
 │   │    │   └──────────────────────────────────────────────────────────────────┘    │    │  │
 │   │    │                                                                          │    │  │
 │   │    │         ┌────────────────┐  ┌────────────────┐  ┌────────────────┐       │    │  │
 │   │    │         │ nebula-registry│  │  nebula-auth   │  │  nebula-      │       │    │  │
 │   │    │         │ :5000          │  │  :5001         │  │  controller   │       │    │  │
 │   │    │         │                │  │                │  │  :8080        │       │    │  │
 │   │    │         │ mTLS (future)  │◄─┤ mTLS (future)  │  │               │       │    │  │
 │   │    │         └───────┬────────┘  └───────┬────────┘  └───────┬───────┘       │    │  │
 │   │    │                 │                   │                   │               │    │  │
 │   │    └─────────────────┼───────────────────┼───────────────────┼───────────────┘    │  │
 │   │                      │                   │                   │                    │  │
 │   │    ┌─────────────────▼───────────────────▼───────────────────▼────────────────┐   │  │
 │   │    │                       BACKEND SERVICES ZONE                               │   │  │
 │   │    │                                                                           │   │  │
 │   │    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                    │   │  │
 │   │    │  │ Object Store │  │  Vault       │  │ K8s API      │                    │   │  │
 │   │    │  │ (S3/GCS)     │  │  (Transit +  │  │ Server       │                    │   │  │
 │   │    │  │              │  │   KV)        │  │              │                    │   │  │
 │   │    │  │ TLS in       │  │ mTLS         │  │ mTLS         │                    │   │  │
 │   │    │  │ transit      │  │              │  │              │                    │   │  │
 │   │    │  │ SSE at rest  │  │              │  │              │                    │   │  │
 │   │    │  └──────────────┘  └──────────────┘  └──────────────┘                    │   │  │
 │   │    └───────────────────────────────────────────────────────────────────────────┘   │  │
 │   └───────────────────────────────────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Encryption Summary

| Segment                           | Protocol    | Details                                    |
|-----------------------------------|------------- |-------------------------------------------|
| Client to Ingress                 | TLS 1.2+   | Cert-manager or ACM; HSTS headers          |
| Ingress to registry/auth pods     | HTTP (in-cluster) | Or mTLS with service mesh (Istio/Linkerd) |
| Registry to Object Store          | TLS         | S3/GCS SDK enforces TLS; SSE at rest       |
| Auth to OIDC Providers            | TLS 1.2+   | Outbound HTTPS for JWKS fetch              |
| Auth/Controller to Vault          | mTLS        | Vault agent injector or direct TLS         |
| Controller to K8s API             | mTLS        | Service account token; TLS always          |
| Prometheus scraping metrics       | HTTP (in-cluster) | mTLS optional via service mesh        |
| Data at rest (object store)       | SSE-S3/KMS  | AES-256; key managed by cloud provider     |
| JWT signing keys at rest          | K8s Secret  | Encrypted at rest via etcd encryption      |

### 8.3 Pod Security Standards

All NebulaCR pods run with hardened security contexts (from `values.yaml`):

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534         # nobody
  runAsGroup: 65534
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
```

---

## 9. CI/CD Integration Patterns

### 9.1 GitHub Actions OIDC Flow

```
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  GitHub Actions Workflow                                                 │
  │                                                                          │
  │  permissions:                                                            │
  │    id-token: write    # Required for OIDC                                │
  │    contents: read                                                        │
  │                                                                          │
  │  steps:                                                                  │
  │    - name: Get OIDC token                                                │
  │      id: oidc                                                            │
  │      uses: actions/github-script@v7                                      │
  │      with:                                                               │
  │        script: |                                                         │
  │          const token = await core                                        │
  │            .getIDToken('nebulacr');                                       │
  │          core.setOutput('token', token);                                 │
  │                                                                          │
  │    - name: Login to NebulaCR                                             │
  │      run: |                                                              │
  │        TOKEN=$(curl -s -X POST \                                         │
  │          https://registry.example.com/auth/token \                       │
  │          -H "Content-Type: application/json" \                           │
  │          -d "{                                                           │
  │            \"identity_token\": \"$OIDC_TOKEN\",                          │
  │            \"scope\": {                                                  │
  │              \"tenant\": \"acme\",                                       │
  │              \"project\": \"backend\",                                   │
  │              \"actions\": [\"push\", \"pull\"]                           │
  │            }                                                             │
  │          }" | jq -r .token)                                              │
  │        echo "$TOKEN" | docker login \                                    │
  │          registry.example.com \                                          │
  │          -u oauth2 --password-stdin                                      │
  │                                                                          │
  │    - name: Push image                                                    │
  │      run: |                                                              │
  │        docker push registry.example.com/                                 │
  │          acme/backend/api:${{ github.sha }}                              │
  └──────────────────────────────────────────────────────────────────────────┘

  Trust chain:
    GitHub OIDC Provider ──signs──► ID Token (sub=repo:acme/api:...)
                                         │
                                         ▼
    nebula-auth ──validates via JWKS──► Extracts subject
                ──checks RBAC──────────► Issues access JWT
                                         │
                                         ▼
    nebula-registry ──validates JWT──► Authorizes push
```

### 9.2 GitLab CI OIDC Flow

```
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  .gitlab-ci.yml                                                          │
  │                                                                          │
  │  push-image:                                                             │
  │    image: docker:24                                                      │
  │    id_tokens:                                                            │
  │      NEBULA_TOKEN:                                                       │
  │        aud: nebulacr                                                     │
  │    script:                                                               │
  │      - |                                                                 │
  │        ACCESS_TOKEN=$(curl -s -X POST \                                  │
  │          https://registry.example.com/auth/token \                       │
  │          -H "Content-Type: application/json" \                           │
  │          -d "{                                                           │
  │            \"identity_token\": \"$NEBULA_TOKEN\",                        │
  │            \"scope\": {                                                  │
  │              \"tenant\": \"acme\",                                       │
  │              \"project\": \"backend\",                                   │
  │              \"actions\": [\"push\", \"pull\"]                           │
  │            }                                                           │
  │          }" | jq -r .token)                                              │
  │      - echo "$ACCESS_TOKEN" | docker login \                             │
  │          registry.example.com -u oauth2 --password-stdin                 │
  │      - docker push registry.example.com/acme/backend/api:$CI_COMMIT_SHA │
  └──────────────────────────────────────────────────────────────────────────┘

  Trust chain:
    GitLab OIDC (iss: https://gitlab.com) ──signs──► ID Token
      sub: "project_path:acme/api:ref_type:branch:ref:main"
```

### 9.3 Jenkins + Vault Flow

```
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  Jenkinsfile                                                             │
  │                                                                          │
  │  pipeline {                                                              │
  │    agent any                                                             │
  │    stages {                                                              │
  │      stage('Push') {                                                     │
  │        steps {                                                           │
  │          // Jenkins has no native OIDC. Use Vault for identity.          │
  │          withVault(                                                      │
  │            vaultSecrets: [[                                               │
  │              path: 'nebulacr/creds/jenkins',                             │
  │              secretValues: [                                              │
  │                [envVar: 'IDENTITY_TOKEN',                                │
  │                 vaultKey: 'token']                                        │
  │              ]                                                           │
  │            ]]                                                            │
  │          ) {                                                              │
  │            sh '''                                                         │
  │              ACCESS=$(curl -s -X POST \                                   │
  │                $REGISTRY_URL/auth/token \                                 │
  │                -d "{ ... }" | jq -r .token)                              │
  │              echo "$ACCESS" | docker login ... --password-stdin           │
  │              docker push ...                                              │
  │            '''                                                            │
  │          }                                                               │
  │        }                                                                 │
  │      }                                                                   │
  │    }                                                                     │
  │  }                                                                       │
  └──────────────────────────────────────────────────────────────────────────┘

  Trust chain:
    Vault ──issues short-lived identity token──► Jenkins
    nebula-auth ──validates Vault-signed JWT──► Issues access JWT
```

### 9.4 ArgoCD + Kubernetes ServiceAccount Flow

```
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  ArgoCD Application (pull-only)                                          │
  │                                                                          │
  │  ArgoCD runs as a K8s ServiceAccount with projected                      │
  │  OIDC token (audience: nebulacr).                                        │
  │                                                                          │
  │  Flow:                                                                   │
  │    1. ArgoCD pod mounts projected service account token:                 │
  │       /var/run/secrets/tokens/nebulacr-token                             │
  │       (audience: "nebulacr", expiry: 10m)                                │
  │                                                                          │
  │    2. Image pull uses this token as identity_token                       │
  │       in POST /auth/token request                                        │
  │                                                                          │
  │    3. nebula-auth validates the K8s-issued JWT:                          │
  │       iss: https://kubernetes.default.svc                                │
  │       sub: system:serviceaccount:argocd:argocd-server                    │
  │       aud: nebulacr                                                      │
  │                                                                          │
  │    4. AccessPolicy grants Reader role to                                 │
  │       "system:serviceaccount:argocd:argocd-server"                       │
  │       on tenant "acme" (pull-only)                                       │
  │                                                                          │
  │  K8s ServiceAccount token spec:                                          │
  │    volumes:                                                              │
  │      - name: nebulacr-token                                              │
  │        projected:                                                        │
  │          sources:                                                         │
  │            - serviceAccountToken:                                         │
  │                audience: nebulacr                                         │
  │                expirationSeconds: 600                                     │
  │                path: token                                                │
  └──────────────────────────────────────────────────────────────────────────┘
```

### 9.5 Comparison Matrix

| Feature                    | GitHub Actions  | GitLab CI       | Jenkins + Vault | ArgoCD + K8s SA |
|---------------------------|-----------------|-----------------|-----------------|-----------------|
| Native OIDC               | Yes             | Yes             | No (via Vault)  | Yes (projected) |
| Secret-free               | Yes             | Yes             | Near (Vault)    | Yes             |
| Token lifetime            | ~10 min         | ~5 min          | Configurable    | ~10 min         |
| Subject identity          | repo:org/repo   | project_path    | vault role      | SA name         |
| Branch/ref pinning        | Yes (ref claim) | Yes (ref claim) | Manual          | N/A             |
| Recommended actions       | push + pull     | push + pull     | push + pull     | pull only       |

---

## 10. Observability Stack

### 10.1 Metrics Pipeline

```
  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
  │nebula-registry│     │ nebula-auth  │     │nebula-controller│
  │  :9090/metrics│     │  :9091/metrics│     │  :8080/metrics│
  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
         │                    │                    │
         │  Prometheus scrape (ServiceMonitor, 30s interval)
         │                    │                    │
         ▼                    ▼                    ▼
  ┌──────────────────────────────────────────────────────────┐
  │                     PROMETHEUS                            │
  │                                                           │
  │  Key metrics:                                             │
  │  ┌─────────────────────────────────────────────────────┐  │
  │  │ registry_auth_requests_total                        │  │
  │  │ registry_token_issued_total                         │  │
  │  │ registry_auth_failures_total{reason}                │  │
  │  │ registry_http_requests_total{method,path,status}    │  │
  │  │ registry_http_request_duration_seconds{quantile}    │  │
  │  │ registry_blob_upload_bytes_total                    │  │
  │  │ registry_storage_operations_total{op,status}        │  │
  │  │ controller_reconcile_total{crd,result}              │  │
  │  │ controller_reconcile_duration_seconds               │  │
  │  │ controller_workqueue_depth{name}                    │  │
  │  └─────────────────────────────────────────────────────┘  │
  │                                                           │
  │  Recording rules:                                         │
  │   - registry:request_rate:5m                              │
  │   - registry:error_rate:5m                                │
  │   - registry:p99_latency:5m                               │
  │                                                           │
  │  Alert rules:                                             │
  │   - HighAuthFailureRate (>5% of requests in 5m)           │
  │   - RegistryDown (0 healthy pods)                         │
  │   - TokenIssuanceLatency (p99 > 500ms)                    │
  │   - StorageErrorRate (>1% of ops failing)                 │
  │   - HighRateLimitHits (>100/min per tenant)               │
  │   - CRDReconcileFailures (>3 consecutive)                 │
  └──────────────────────┬───────────────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────┐
  │                      GRAFANA                              │
  │                                                           │
  │  Dashboards:                                              │
  │  ┌─────────────────────────────────────────────────────┐  │
  │  │ 1. Registry Overview                                │  │
  │  │    - Request rate, error rate, latency (p50/p99)    │  │
  │  │    - Active uploads, blob throughput                 │  │
  │  │                                                     │  │
  │  │ 2. Auth Service                                     │  │
  │  │    - Token issuance rate, failure breakdown          │  │
  │  │    - Rate limit hits per tenant                     │  │
  │  │    - OIDC validation latency                        │  │
  │  │                                                     │  │
  │  │ 3. Per-Tenant View                                  │  │
  │  │    - Storage usage, repository count                │  │
  │  │    - Request rate, quota utilization                 │  │
  │  │    - Top repositories by pull count                 │  │
  │  │                                                     │  │
  │  │ 4. Controller Health                                │  │
  │  │    - Reconcile rate, errors, queue depth             │  │
  │  │    - CRD counts by type and status                  │  │
  │  └─────────────────────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────┘
```

### 10.2 Logging Pipeline

```
  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
  │nebula-registry│     │ nebula-auth  │     │nebula-controller│
  │ (JSON stdout) │     │ (JSON stdout) │     │ (JSON stdout) │
  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
         │                    │                    │
         │  Container stdout/stderr                │
         │                    │                    │
         ▼                    ▼                    ▼
  ┌──────────────────────────────────────────────────────────┐
  │                  FLUENT BIT (DaemonSet)                    │
  │                                                           │
  │  Filters:                                                 │
  │  - Kubernetes metadata enrichment (pod, namespace, node)  │
  │  - Parse JSON log format                                  │
  │  - Add tenant_id label from structured log field          │
  │  - Redact sensitive fields (tokens, keys)                 │
  │  - Drop debug-level logs in production                    │
  └──────────────────────┬───────────────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────┐
  │              ELASTICSEARCH / OPENSEARCH                    │
  │                                                           │
  │  Indices:                                                 │
  │  - nebulacr-auth-YYYY.MM.DD                               │
  │  - nebulacr-registry-YYYY.MM.DD                           │
  │  - nebulacr-controller-YYYY.MM.DD                         │
  │  - nebulacr-audit-YYYY.MM.DD  (audit events)              │
  │                                                           │
  │  Retention: 30 days (configurable)                        │
  └──────────────────────┬───────────────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────┐
  │               KIBANA / OPENSEARCH DASHBOARDS              │
  │                                                           │
  │  Saved searches:                                          │
  │  - Auth failures by tenant                                │
  │  - Token issuance audit trail                             │
  │  - Storage errors                                         │
  │  - Rate limit events                                      │
  └──────────────────────────────────────────────────────────┘

  Log format (nebula-auth example):
  {
    "timestamp": "2026-03-25T12:00:00.000Z",
    "level": "INFO",
    "target": "nebula_auth::handlers",
    "message": "token issued",
    "request_id": "a1b2c3d4-...",
    "subject": "repo:acme/api:ref:refs/heads/main",
    "tenant_id": "550e8400-...",
    "role": "maintainer",
    "file": "src/main.rs",
    "line": 420
  }
```

### 10.3 Distributed Tracing Pipeline

```
  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
  │nebula-registry│     │ nebula-auth  │     │nebula-controller│
  │ (OTLP gRPC)  │     │ (OTLP gRPC)  │     │ (OTLP gRPC)  │
  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
         │                    │                    │
         │  OpenTelemetry SDK (tracing spans)      │
         │  W3C Trace Context propagation          │
         │                    │                    │
         ▼                    ▼                    ▼
  ┌──────────────────────────────────────────────────────────┐
  │              OTEL COLLECTOR (Deployment)                   │
  │                                                           │
  │  Receivers:  otlp (gRPC :4317, HTTP :4318)                │
  │  Processors: batch, tail_sampling (0.1 ratio),            │
  │              attributes (add cluster, region)              │
  │  Exporters:  jaeger, tempo, or cloud-native               │
  └──────────────────────┬───────────────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────────────────┐
  │              JAEGER / GRAFANA TEMPO                        │
  │                                                           │
  │  Trace structure for a Docker push:                       │
  │                                                           │
  │  [registry] POST /v2/.../blobs/uploads/                   │
  │    ├── [registry] auth.validate_jwt          (0.2ms)      │
  │    ├── [registry] storage.create_upload       (1.5ms)     │
  │    └── [registry] http.response              (2.1ms)      │
  │                                                           │
  │  [registry] PUT /v2/.../blobs/uploads/<uuid>              │
  │    ├── [registry] auth.validate_jwt          (0.2ms)      │
  │    ├── [registry] storage.write_blob         (45ms)       │
  │    ├── [registry] storage.verify_digest      (12ms)       │
  │    └── [registry] http.response              (58ms)       │
  │                                                           │
  │  [registry] PUT /v2/.../manifests/v1.0.0                  │
  │    ├── [registry] auth.validate_jwt          (0.2ms)      │
  │    ├── [registry] manifest.validate          (0.5ms)      │
  │    ├── [registry] storage.write_manifest     (3ms)        │
  │    ├── [registry] storage.write_tag_link     (1ms)        │
  │    └── [registry] http.response              (5ms)        │
  └──────────────────────────────────────────────────────────┘
```

---

## 11. Threat Model Diagram

### 11.1 STRIDE Analysis Overlay

The following diagram annotates the system overview with numbered threat vectors.
Each threat is categorized using STRIDE (Spoofing, Tampering, Repudiation,
Information Disclosure, Denial of Service, Elevation of Privilege).

```
                                  THREAT MODEL OVERLAY
 ═══════════════════════════════════════════════════════════════════════════════

                              UNTRUSTED ZONE
    ┌──────────┐
    │ Attacker │
    └────┬─────┘
         │
         │  [T1] [T2] [T3] [T6] [T7] [T8]
         │
         ▼
    ┌──────────────────────┐
    │    INGRESS / LB      │◄──── TRUST BOUNDARY 1
    │                      │       (TLS termination)
    └──────────┬───────────┘
               │
               │  [T4] [T5]
               │
    ═══════════╪═══════════════ TRUST BOUNDARY 2 (cluster network)
               │
         ┌─────┴──────┐
         │            │
         ▼            ▼
    ┌─────────┐  ┌─────────┐
    │registry │  │  auth   │◄──── [T9] [T10]
    │         │  │         │
    └────┬────┘  └────┬────┘
         │            │
         │  [T11]     │  [T12]
         │            │
         ▼            ▼
    ┌─────────┐  ┌──────────────┐
    │ Object  │  │OIDC Provider │◄──── TRUST BOUNDARY 3
    │ Storage │  │ (external)   │       (external dependency)
    └─────────┘  └──────────────┘
```

### 11.2 Threat Catalog

```
  ID    Category    Threat Description                              Mitigation
  ──── ─────────── ──────────────────────────────────────────────── ─────────────────────────────────────────
  T1    Spoofing    Attacker presents forged OIDC token             JWKS-based signature verification;
                    to obtain registry access.                      tokens validated against provider's
                                                                    public keys fetched from discovery
                                                                    endpoint. Key rotation handled by
                                                                    JWKS cache with TTL refresh.

  T2    Spoofing    Attacker replays a valid but expired            Strict exp claim validation; short
                    OIDC or access token.                           token TTL (300s default); jti claim
                                                                    for optional replay detection.

  T3    Tampering   Attacker modifies JWT claims (tenant_id,        RS256 signature verification on every
                    role, scopes) in transit.                       request. JWT integrity is cryptographic.

  T4    Tampering   Man-in-the-middle between Ingress and           mTLS between Ingress and pods (via
                    service pods to intercept/modify tokens.        service mesh). NetworkPolicy restricts
                                                                    ingress sources to the LB controller.

  T5    Tampering   Attacker modifies blob content during           Content-addressable storage: blob path
                    upload to inject malicious layers.              includes SHA-256 digest. Upload
                                                                    finalization verifies digest matches
                                                                    content. DigestInvalid error on mismatch.

  T6    Repudiation Attacker performs actions without audit          Every auth decision generates an
                    trail (deny performing push/delete).            AuditEvent with subject, tenant, action,
                                                                    decision, reason, request_id, source_ip.
                                                                    All logs are structured JSON with
                                                                    request_id correlation.

  T7    Info        Attacker enumerates tenants, projects,          Tenant/project names return 404 (not
        Disclosure  or repositories to discover targets.            403) for non-existent resources. Catalog
                                                                    endpoint requires authentication. Rate
                                                                    limiting prevents brute-force enumeration.

  T8    Denial of   Attacker floods token issuance or               Per-tenant rate limiting (token_issue_rpm).
        Service     registry endpoints to exhaust resources.        Per-IP rate limiting at Ingress (ip_rps).
                                                                    HPA auto-scales under load. PDB ensures
                                                                    minimum availability during disruptions.

  T9    Elevation   Attacker with Reader role attempts to           Token scopes explicitly list allowed
        of          push or delete images.                          actions. Registry checks scope.actions
        Privilege                                                   on every request. Role hierarchy is
                                                                    enforced: Reader cannot push. RBAC
                                                                    evaluation intersects requested actions
                                                                    with role permissions.

  T10   Elevation   Attacker creates token for tenant A and         JWT contains tenant_id. Registry validates
        of          attempts to access tenant B's resources.        that token's tenant_id matches the
        Privilege                                                   request path prefix. Storage paths
                                                                    enforce tenant isolation. Cross-tenant
                                                                    tokens cannot be issued.

  T11   Info        Attacker gains access to object storage         SSE at rest (AES-256). IAM policies
        Disclosure  bucket and reads image data directly.           restrict bucket access to registry
                                                                    service account only. Bucket is not
                                                                    publicly accessible. VPC endpoint for
                                                                    S3 avoids public internet.

  T12   Spoofing    Attacker compromises OIDC provider or           Multiple OIDC providers configured
                    performs DNS hijack of JWKS endpoint.           independently. JWKS endpoints use TLS
                                                                    with certificate validation. Optional
                                                                    JWKS pinning. Audit log flags unusual
                                                                    issuer patterns.

  T13   Tampering   Attacker with K8s access modifies CRDs          RBAC on K8s API: only nebula-controller
                    to escalate their NebulaCR permissions.         SA can watch/update CRDs. Webhook
                                                                    validation (future) rejects invalid
                                                                    CRD changes. Audit log in K8s tracks
                                                                    all CRD mutations.

  T14   Denial of   Attacker creates excessive Tenants/Projects     CRD quotas: ResourceQuota on namespace
        Service     via K8s API to exhaust controller resources.    limits CRD count. Controller uses
                                                                    rate-limited work queue. Leader election
                                                                    prevents split-brain.
```

### 11.3 Trust Boundary Summary

```
  Boundary    Location                     What Crosses It                Validation
  ────────── ──────────────────────────── ────────────────────────────── ──────────────────────────
  TB1         Internet ↔ Ingress           Client HTTPS requests          TLS certificate; WAF rules;
                                                                          IP rate limiting

  TB2         Ingress ↔ Cluster services   HTTP requests (post-TLS)       NetworkPolicy; JWT validation
                                                                          at service level; mTLS (future)

  TB3         Cluster ↔ External OIDC      JWKS fetch; token validation   TLS to provider; cached JWKS;
                                                                          signature verification

  TB4         Cluster ↔ Object Storage     Blob/manifest read/write       IAM authentication; TLS;
                                                                          VPC endpoint; SSE at rest

  TB5         Cluster ↔ Vault              Key signing; secret retrieval  mTLS; Vault token auth;
                                                                          short-lived leases

  TB6         K8s API ↔ Controller         CRD watch/update               ServiceAccount RBAC; mTLS;
                                                                          audit logging
```

---

## Appendix A: Configuration Reference

Key configuration values from `RegistryConfig` (see `nebula-common/src/config.rs`):

| Section         | Field                   | Default                          | Description                          |
|-----------------|-------------------------|----------------------------------|--------------------------------------|
| server          | listen_addr             | 0.0.0.0:5000                     | Registry API bind address            |
| server          | auth_listen_addr        | 0.0.0.0:5001                     | Auth service bind address            |
| server          | metrics_addr            | 0.0.0.0:9090                     | Metrics endpoint bind address        |
| auth            | signing_algorithm       | RS256                            | JWT signing algorithm                |
| auth            | signing_key_path        | /etc/nebulacr/keys/private.pem   | RSA private key for signing          |
| auth            | verification_key_path   | /etc/nebulacr/keys/public.pem    | RSA public key for verification      |
| auth            | token_ttl_seconds       | 300                              | Access token lifetime (5 min)        |
| auth            | issuer                  | nebulacr                         | JWT `iss` claim value                |
| auth            | audience                | nebulacr-registry                | JWT `aud` claim value                |
| storage         | backend                 | filesystem                       | Storage backend type                 |
| storage         | root                    | /var/lib/nebulacr/data           | Root path or bucket name             |
| rate_limit      | default_rps             | 100                              | Per-tenant requests/second           |
| rate_limit      | ip_rps                  | 50                               | Per-IP requests/second (unauthed)    |
| rate_limit      | token_issue_rpm         | 60                               | Token issuance requests/minute       |
| observability   | log_level               | info                             | Log verbosity filter                 |
| observability   | log_format              | json                             | Log output format                    |
| observability   | otlp_endpoint           | (none)                           | OTLP collector gRPC endpoint         |

## Appendix B: CRD API Group

All CRDs belong to the `nebulacr.io` API group, version `v1alpha1`.

| CRD            | Scope      | Short Name | Key Fields                                          |
|----------------|------------|------------|-----------------------------------------------------|
| Tenant         | Cluster    | tn         | displayName, adminEmail, enabled, quotas             |
| Project        | Namespaced | proj       | tenantRef, visibility, immutableTags, retention      |
| AccessPolicy   | Namespaced | ap         | tenantRef, subjects, resources, actions, effect      |
| TokenPolicy    | Namespaced | tp         | tenantRef, maxTokenLifetime, rotation, revocation    |

## Appendix C: Error Code Mapping

NebulaCR maps internal errors to OCI Distribution error codes (from `nebula-common/src/errors.rs`):

| Internal Error       | OCI Code              | HTTP Status | Description                        |
|---------------------|-----------------------|-------------|------------------------------------|
| BlobUnknown         | BLOB_UNKNOWN          | 404         | Referenced blob does not exist     |
| BlobUploadInvalid   | BLOB_UPLOAD_INVALID   | 400         | Upload session is invalid          |
| DigestInvalid       | DIGEST_INVALID        | 400         | Digest mismatch on finalization    |
| ManifestUnknown     | MANIFEST_UNKNOWN      | 404         | Referenced manifest not found      |
| ManifestInvalid     | MANIFEST_INVALID      | 400         | Manifest failed validation         |
| NameUnknown         | NAME_UNKNOWN          | 404         | Repository/tenant/project not found|
| Unauthorized        | UNAUTHORIZED          | 401         | Missing or invalid credentials     |
| Forbidden           | DENIED                | 403         | Insufficient permissions           |
| RateLimitExceeded   | TOOMANYREQUESTS       | 429         | Rate limit exceeded                |
| TokenExpired        | UNAUTHORIZED          | 401         | JWT has expired                    |
| Internal/Storage    | UNKNOWN               | 500         | Server-side error                  |
