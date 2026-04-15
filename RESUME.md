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

## Session checkpoint (2026-04-15 → 2026-04-16)

### Latest commits
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

### Known not-yet-done (from the original spec)
1. **Own CVE DB (slice 2)** — ingestion jobs for NVD 2.0 API + OSV rsync + GHSA GraphQL → Postgres tables `vulnerabilities` / `affected_ranges` → swap `OsvClient` for `NebulaVulnDb` via config flip `NEBULACR_SCANNER__VULNDB=nebula`. **Biggest outstanding item.** 3-4 weeks realistic. User picked option **C** explicitly.
2. **RPM SBOM parser** — needs BDB + sqlite header-blob decoding. Affects RHEL/UBI/CentOS images only.
3. **Ecosystem version comparators** (task #8) — only matters once own-DB lands (OSV does its own matching).
4. **`/v2/cve/search`** — needs own-DB; stub returns 501.
5. **Go + Cargo SBOM parsers** — stubs today; modest work (`go.sum` parser, `Cargo.lock` TOML parser).
6. **AI sequential bottleneck** — `analyse_all` calls Ollama one CVE at a time. Parallelise (bounded fan-out) when GPU is free.
7. **Bonus items from original spec**: HTML report, S3 export, GitHub PR automation, VEX, SPDX, Dockerfile auto-fix suggestions. No concrete consumer yet — defer until asked.

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

### For slice 2 (own CVE DB) when you pick it up

Design starting point I'd propose (get user confirmation first):

- New binary crate `nebula-vulndb-ingest` (or a subcommand of `nebula-registry`)
- Three ingesters as tokio tasks on separate schedules:
  - `nvd`: NVD 2.0 API, 5-minute pages, persist `last_modified` cursor
  - `osv`: rsync the `all.zip` from `https://osv-vulnerabilities.storage.googleapis.com/` once/6h
  - `ghsa`: GitHub GraphQL `securityAdvisories` query, 1h schedule
- Normaliser trait `Ingester -> Vec<NormalisedAdvisory>`
- Write path: UPSERT into `vulnerabilities` + DELETE-then-INSERT into `affected_ranges` inside a transaction per advisory
- Matcher: `NebulaVulnDb::query` joins `affected_ranges` by `(ecosystem, package)`, then calls the per-ecosystem comparator from `matcher/`

The trait boundary at `VulnDb` is already there; flipping
`NEBULACR_SCANNER__VULNDB=nebula` swaps implementations with zero caller changes.
