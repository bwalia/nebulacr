# NebulaCR — Next-Major-Release Design Prompt

> Hand this prompt to a planning agent (or paste into a fresh Claude session)
> to generate the per-feature design documents under `docs/design/`.

---

You are designing the next major release of NebulaCR, a Rust-based OCI
container registry (https://github.com/bwalia/nebulacr).

## Current state

- Workspace crates: `nebula-registry`, `nebula-auth`, `nebula-common`,
  `nebula-controller`, `nebula-mirror`, `nebula-resilience`,
  `nebula-replication`, `nebula-scanner` (in-progress), `nebula-ai`,
  `nebula-db`.
- OCI Distribution v2 + pull-through cache (Docker Hub, GHCR, GCR, Quay,
  registry.k8s.io).
- Multi-tenancy via CRDs: `Tenant`, `Project`, `AccessPolicy`, `TokenPolicy`.
- OIDC auth, JWT issuance, RBAC.
- Storage backends: filesystem, S3, GCS, Azure Blob.
- Multi-region replication, Prometheus metrics, OTel tracing.
- Scanner slice in flight: own CVE DB (OSV / NVD / GHSA → Postgres),
  Ollama-based AI remediation, suppressions in Postgres, scan results in
  Redis (ephemeral, 1h TTL).
- CLI binary: `nebulacr`. MCP server: `nebula-mcp`.

## Goal

Close the eight highest-leverage gaps against Azure Container Registry and
Sonatype Nexus, in priority order:

1. **Cosign/Notation image signing + verification policies**
2. **Pull-time admission gate** ("registry firewall") wired to the scanner
3. **Tag immutability + quarantine state machine**
4. **Garbage collection + retention policies** (reference-counted; age, count, regex)
5. **Append-only signed audit log**
6. **Atomic promotion API** across projects / tenants
7. **Web UI parity**: browse, manifest viewer, scan report, signatures, audit
8. **CMK / envelope encryption at rest** (per-tenant KEK in KMS / Vault)

## Deliverable

Produce a design document with the following sections for **each** of the
eight features:

a. **Problem statement** — one paragraph; what Nexus / ACR do that we don't.
b. **Proposed approach** — Rust crate boundaries, traits, data model deltas.
c. **New/changed CRDs** — full YAML examples.
d. **New HTTP routes** — path + verb + auth scope + payload shape.
e. **Storage / Postgres schema** — DDL, indexed columns.
f. **Failure modes** — how the design degrades (KMS unavailable, GC race, etc.).
g. **Migration story** — no-op default, opt-in flag for existing deployments.
h. **Test plan** — which crate, what's mocked, what needs real Postgres / S3.
i. **Implementation slice count** — calibrated against the scanner work
   (~3–4 weeks of effort).

## Cross-cutting constraints

- **Stay pure-Rust.** No shelling out to `cosign` / `notation` binaries —
  use `sigstore-rs` and `notary-rs` behind a `Signer` / `Verifier` trait so
  alternate impls are pluggable.
- **New persistent state goes in Postgres** (already a dependency for the
  scanner). Do NOT introduce a new datastore. Redis stays ephemeral-only.
- **All new APIs must work** with both 2-segment (default-tenant) and
  3-segment (tenant/project/repo) paths.
- **Every feature must have a kill-switch** in `nebulacr.toml` and default
  to OFF for the first release that ships it. Existing deployments must
  not break on upgrade.
- **Honour the locked decisions** in project memory:
  - VulnDB behind a trait.
  - Queue behind a trait.
  - Suppressions / audit Postgres-persisted; scan results Redis-ephemeral.
  - Distro-version collapsed to family in `affected_ranges.ecosystem`.
  - `vulnerabilities.source` classified by advisory-ID prefix.
- **CLI + MCP surfaces** (`nebulacr sign / verify / promote / gc / audit / key`,
  `nebula-mcp` tools) must be designed alongside each feature, not bolted on later.

## Output format

- Markdown, one file per feature under `docs/design/00X-<slug>.md`.
- A top-level `docs/design/README.md` indexing them with status
  (`proposed` / `accepted` / `in-progress` / `shipped`) and dependency
  arrows (e.g. "promotion depends on signing").
- Identify the **critical path**: which two features unblock the most
  others if shipped first.

## Non-goals (do NOT design these)

- Multi-format support (npm, PyPI, Maven, Helm-non-OCI) — out of scope.
- ACR Tasks / build automation — out of scope.
- Connected / edge registry — deferred to a later release.
- Replacing OIDC — auth surface is settled.
