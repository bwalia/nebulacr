# NebulaCR Scanner — Resume Prompt

Paste the block below into a fresh Claude Code session after SSH reconnect.
Everything Claude needs to continue is in here; no earlier-session memory
assumed. Keep this file around until the scanner platform is feature-complete.

---

## Resume prompt (copy-paste verbatim)

> I'm resuming work on the NebulaCR image-scanning platform. The work so far
> is in this repo at `/home/bwalia/nebulacr`. Read
> `RESUME.md`, `.claude/projects/-home-bwalia-nebulacr/memory/MEMORY.md`, and
> `git log --oneline -5` to pick up context, then answer with a one-screen
> status summary and propose the next concrete slice. Do NOT start coding
> until I confirm. My GPU contention with `kubepilot` may or may not be
> resolved — if the next slice needs Ollama, ask me to confirm GPU is free
> first.

---

## Session checkpoint (2026-04-15 → 2026-04-16, session 2)

**Four new commits since last checkpoint, all LOCAL (not pushed):**
- `b90f65d` feat(scanner): OSV ingester trait + normaliser (slice 2a)
- `0f574fa` feat(db): schema for vuln-DB ingestion (slice 2a)
- `684b8ab` feat(scanner): Cargo.lock SBOM parser
- `9df1cf9` feat(scanner): go.sum SBOM parser

If this host dies before these are pushed, the work is gone. Consider
`git push origin main` or `git push origin main:wip/slice-2a` before
closing the session.

### Previous checkpoint commits
- `3d95d7f` feat(scanner): per-repo settings + full suppression CRUD + pypi parser
- `14317fd` CVE scanners added (initial scaffolding)

### Stack state
- `docker compose up -d` brings up `postgres`, `redis`, `auth`, `registry`
- Registry is on `localhost:5000`, metrics `localhost:9095`, auth `localhost:5001`
- Scanner workers (2) spin up inside the registry process via `ScannerRuntime`
- `NEBULACR_SCANNER__*` env vars already set in `docker-compose.yml`
- Postgres schema: scans, vulnerabilities, affected_ranges, suppressions, audit_log, image_settings, scanner_api_keys
- Ollama expected at `http://host.docker.internal:11434` with model
  `qwen2.5-coder:7b` — **currently contended by `kubepilot` (pid 7850)**; AI
  path is wired but was timing out at ~5min/CVE

### Proven end-to-end (on this host)
- `alpine:3.16` → 14 apk packages → 12 OSV advisories → 1 crit / 3 high / 5 med / 2 low / 1 unk; policy rule `block_if.critical:">0"` flips to FAIL
- `python:3.9-slim` → 265 packages (92 deb + 12 pypi + rest noise) → 104 CVEs (2 crit, 32 high, 47 med, 7 low, 16 unk)
- Suppression create → list → revoke → audit log rows present
- `scan_enabled=false` gate: worker logs `scan skipped`

### Slice 2a — own CVE DB (OSV-only first pass), in progress

User locked option C for own-DB. Decisions + progress so far:

Locked design decisions:
- **Distro-version precision**: collapse `Alpine:v3.16` → `apk`, `Debian:11` → `deb`, etc. Lose per-distro-version matching for 2a; revisit with NVD/GHSA.
- **`source` column is developer-friendly**: classify by ID prefix — `CVE-*` → `nvd`, `GHSA-*` → `ghsa`, `PYSEC-*` → `pysec`, `GO-*` → `go`, `ALSA|DLA|DSA|USN|RHSA|RLSA-*` → `distro`, else `osv`. Filtering `WHERE source='nvd'` returns what a dev expects.
- **`ingest_enabled=true` by default**, with a one-shot `warn!` on first run warning operators about the ~300MB `all.zip` download.

Done (committed locally):
- Migration `0002_vulndb_ingest.sql`: `ingest_cursor` table + indexes on `affected_ranges(vuln_id)` and `vulnerabilities(modified_at DESC)`. Already applied to running Postgres.
- `vulndb/severity.rs`: extracted CVSS helpers (`parse_cvss_base`, `cvss3_base`, `classify`) out of `osv.rs` so ingesters and the online client share severity classification.
- `vulndb/ingest/mod.rs`: `Ingester` trait (async, takes `&PgPool`), `IngestStats`, `VulnerabilityRow`, `AffectedRangeRow` — the DB-row shapes produced by the pure normaliser.
- `vulndb/ingest/normalise.rs`: OSV JSON → `(VulnerabilityRow, Vec<AffectedRangeRow>)`, with 8 fixture tests covering multi-event ranges, `last_affected`, unclosed `introduced`, withdrawn filtering, distro-suffix collapse, ecosystem mapping table, source classifier.

Next up (commit 3 of 2a) — **OSV zip ingester + writer + scheduler + admin endpoint**:
- Add `zip = "2"` dependency.
- Stream `all.zip` from `https://osv-vulnerabilities.storage.googleapis.com/` to a tempfile (never fully into memory).
- Iterate entries with `zip::ZipArchive::by_index`, feed each `.json` to `normalise()`, UPSERT + DELETE-then-INSERT in a per-advisory tx.
- Persist ETag to `ingest_cursor` so subsequent runs short-circuit on 304.
- Config fields: `ingest_enabled: bool (default true)`, `ingest_interval_secs: u64 (default 21600)`.
- Spawn scheduler from `ScannerRuntime::build`; first-run banner uses `warn!`.
- `POST /admin/vulndb/ingest` — auth-gated manual trigger for dev.

After that (commit 4 of 2a) — **`NebulaVulnDb::query` + smoke test**:
- Per-package `SELECT ... FROM affected_ranges JOIN vulnerabilities ...`, filter via `matcher::for_ecosystem()`.
- Re-scan `alpine:3.16` under `NEBULACR_SCANNER__VULNDB=nebula`; compare to baseline (1 crit / 3 high / 5 med / 2 low / 1 unk). ±a couple acceptable.

Other not-yet-done (parked behind 2a):
1. **RPM SBOM parser** — BDB + sqlite header-blob decoding. RHEL/UBI/CentOS only.
2. **Ecosystem version comparators** (task #8) — needed once own-DB lands.
3. **`/v2/cve/search`** — needs own-DB; stub returns 501.
4. **AI sequential bottleneck** — `analyse_all` one CVE at a time. Parallelise when GPU free.
5. **Bonus items** from original spec: HTML report, S3 export, GitHub PR automation, VEX, SPDX, Dockerfile auto-fix. No consumer yet — defer until asked.

Done (earlier in this session, as commits above):
- **Go SBOM parser** (`go.sum`, dedups `/go.mod` lines, handles pseudo-versions + `+incompatible`).
- **Cargo SBOM parser** (`Cargo.lock`, via `toml` crate, excludes sourceless packages).

### Known pre-existing registry bugs I had to patch
- `/v2/` returned 200 without auth → fixed to return 401 + WWW-Authenticate
- WWW-Authenticate realm defaulted to `https://` → set `NEBULACR_EXTERNAL_URL`
- `/auth/token` proxy hardcoded to `nebulacr-auth:5001` → set `NEBULACR_AUTH_SERVICE_URL`
- JWT keys owned by root, auth uid is 10001 → `chown` on the volume. If the volume gets recreated this will break again; long-term fix is to update the `keygen` init-container to chown before writing.

### How to smoke-test after restart

```bash
cd /home/bwalia/nebulacr
docker compose up -d
sleep 6
docker compose logs registry | grep "scanner runtime ready"  # expect 1 line

docker login localhost:5000 -u admin -p admin     # should say "Login Succeeded"
docker pull alpine:3.16
docker tag alpine:3.16 localhost:5000/demo/default/alpine:3.16
docker push localhost:5000/demo/default/alpine:3.16

# Wait a couple seconds, then:
DIGEST=sha256:0db9d004361b106932f8c7632ae54d56e92c18281e2dd203127d77405020abf6
TOKEN=$(curl -s -u admin:admin "http://localhost:5000/auth/token?service=nebulacr-registry&scope=repository:demo/default/alpine:pull" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:5000/v2/scan/live/$DIGEST" | python3 -m json.tool | head -40
```

Expected: `summary.critical = 1`, `policy_evaluation.status = FAIL` (if the
per-repo rule from the previous session persisted via volume — it lives in
Postgres, so yes).

### Test verification

All 32 scanner lib tests green as of `b90f65d`. Run in container:

```bash
docker run --rm -v /home/bwalia/nebulacr:/build -w /build \
  -e CARGO_HOME=/build/.cargo-home rust:1.94-bookworm \
  cargo test -p nebula-scanner --lib
```

No Rust toolchain installed directly on the host — the project always
builds via the `rust:1.94-bookworm` image.

### NVD / GHSA (slices 2b / 2c, after 2a lands)

Once 2a is end-to-end:
- `nvd`: NVD 2.0 API, paginated, persist `last_modified` cursor in `ingest_cursor`. 5-min sleep between pages (NVD rate limit).
- `ghsa`: GitHub GraphQL `securityAdvisories` query, 1h schedule. Requires a GH token in config.

Both feed the same `Ingester` trait + normaliser pattern established in 2a.

The trait boundary at `VulnDb` is already there; flipping
`NEBULACR_SCANNER__VULNDB=nebula` swaps implementations with zero caller changes.
