# 007 — Web UI Parity

> **Summary.** Extend the existing skeleton React + Vite app at
> `dashboard/` (currently a CVE-search single page; see
> `dashboard/src/App.tsx`) into a full registry browser. Auth via the
> existing JWT (already used by `dashboard/src/api.ts`). Pages: repo
> browser, tag list, manifest viewer (layers + config), scan report,
> signature viewer, audit timeline, policy editor. Reuse the existing
> `dashboard_auth_middleware`
> (`crates/nebula-registry/src/main.rs:209`) and `/api/*` routes
> (`main.rs:2904-2916`). No new framework.

## a. Problem statement

ACR Portal and Nexus UI are major selling points; users evaluate
registries by clicking around for ten minutes. NebulaCR's dashboard is
a one-page CVE search shipping zero registry-data viewing. The HTTP
APIs work, but no human can use them without `curl`.

## b. Proposed approach

Stack is fixed: React 18 + react-router-dom + Vite + TypeScript (already
in `dashboard/package.json`). Add `@tanstack/react-query` (~13 kB) for
data fetching; pure-CSS for styles to keep the bundle under 200 kB.
No state-management library — react-query covers it.

Information architecture (one route per page):

```
/                        → tenant overview cards
/t/:tenant               → projects in tenant
/t/:tenant/:project      → repos in project
/t/:tenant/:project/:repo                     → tag list
/t/:tenant/:project/:repo/manifest/:ref       → manifest viewer (layers, config, descriptors)
/t/:tenant/:project/:repo/scan/:digest        → scan report (already exists at ScanDetail.tsx)
/t/:tenant/:project/:repo/signatures/:digest  → signature viewer
/audit                   → audit timeline (filter by tenant/actor/category/date)
/policies                → policy editor (admission, verification, retention)
/admin/users             → existing /api/users wired up
/admin/keys              → CMK key list (008)
```

Data sources (all already exist or are added by sibling features):

- Repos / tags: existing `/v2/_catalog`, `/v2/.../tags/list`.
- Scan report: existing `/api/image-detail`
  (`crates/nebula-registry/src/main.rs:2912`) + scanner's `/scan/{digest}`.
- Manifest body: existing `GET /v2/.../manifests/{ref}` — render
  layers, config descriptor, mediaType, history.
- Signatures: `/v2/.../signatures/{digest}` (001).
- Audit: `/v2/_audit` (005).
- Policies: GET/PUT against the controller via a thin proxy route
  `/api/policies/...` (registry forwards).
- Admission test: `/v2/_admit/test` (002).

Auth: `dashboard/src/api.ts` already stores an API key in localStorage
and sends it as `X-API-Key`. Extend to also accept a JWT issued by the
existing auth service; the registry's existing `dashboard_auth_middleware`
can be flipped to "JWT or API key" mode. Login page hits
`POST /auth/token` (existing).

Build is unchanged: `npm run build` produces `dashboard/dist/`, served
by the existing static-file route. The Helm chart already has a
`dashboard.enabled` flag at
`deploy/helm/nebulacr/values.yaml:340-346`.

CLI: nothing — UI is the surface. MCP: `open_in_ui` returns a deep
link given a digest or tag.

## c. New/changed CRDs

None.

## d. New HTTP routes

Most pages reuse routes added by 001–006. Two new lightweight
aggregator routes save round-trips:

| Method | Path                                        | Auth scope        | Notes                              |
| ------ | ------------------------------------------- | ----------------- | ---------------------------------- |
| GET    | `/api/ui/repo-summary?repo=t/p/r`           | dashboard auth    | Combines tag count + last push +   |
|        |                                             |                   | scan summary + sig count           |
| GET    | `/api/ui/tag-detail?repo=t/p/r&tag=...`     | dashboard auth    | Manifest + scan + sig + tag-state  |
|        |                                             |                   | in one request                     |

These are pure read-side aggregators; no new business logic.

## e. Storage / Postgres schema

None. UI is a consumer.

## f. Failure modes

- **Slow scan/audit query** blocks page render. Mitigate with
  react-query stale-while-revalidate + skeleton loaders + per-card
  error boundaries — never one error blanks the page.
- **JWT expiry mid-session.** Interceptor in `api.ts` handles 401 by
  redirecting to login; tokens refreshed via the existing refresh
  token flow.
- **Large manifest viewer.** Some images have 100+ layers; virtualise
  with `react-virtuoso` (~10 kB).

## g. Migration story

`dashboard.enabled = false` (existing). Old single-page CVE search
remains the index when 007 is disabled. When enabled, the new router
takes over but `/scan/:digest` remains a stable URL — the existing
`ScanDetail.tsx` is folded into the new IA.

## h. Test plan

| Layer           | Where                                  | Notes                                            |
| --------------- | -------------------------------------- | ------------------------------------------------ |
| Component tests | `dashboard/src/__tests__/`             | Vitest + Testing Library; no MSW (use fixtures)  |
| API contract    | `dashboard/src/api.ts` typing          | Generated from OpenAPI yaml shipped by registry  |
| E2E             | `tests/e2e/ui.spec.ts`                 | Playwright, runs against `kind` deploy           |
| Visual regress  | `dashboard/snapshots/`                 | Optional; behind `--snap` flag in CI             |

## i. Implementation slice count

4 slices, ~4 weeks:

1. Routing skeleton, login page, tenant + project + repo browsers.
2. Tag list + manifest viewer + scan report integration.
3. Signature viewer + audit timeline + policy list (read-only).
4. Policy editor (write), admission test page, CMK key list page,
   accessibility pass, Helm chart wiring.
