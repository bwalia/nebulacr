# 017 — Cost & Pull-Telemetry Dashboard

> **Summary.** A per-tenant / per-project view of bandwidth (in/out),
> storage bytes, request rate, and projected dollar cost. Sources:
> the existing Prometheus pipeline plus a new `usage_events` table
> that tags every push/pull with `(tenant, project, repo, bytes, ip,
> ua, src=cache|origin|peer)`. Aggregations roll up to 1m / 1h / 1d
> tables (downsampled). Operators get a "showback" report; tenants
> see their own usage; alerts fire on egress anomalies.

## a. Problem statement

Every multi-tenant registry operator faces the same questions on
day 30 in production: which tenant is driving 80 % of egress, which
projects are eating the storage bill, are we about to bust the
monthly S3 budget, and which images are the chatty pulls? ACR has
"Insights" billing dashboards (paid). Nexus has nothing —
operators ETL nginx logs into Grafana by hand. Without first-class
cost attribution, the operator cannot enforce quotas (which the
`Tenant` CRD already declares but does not measure) or charge back.
This is the operator-side counterpart of the security work.

## b. Proposed approach

Two layers:

### 1. Per-event recording

Every storage operation records a row to `usage_events` (Postgres,
batch-inserted in 1-second windows by a writer task to avoid
hot-row contention). Hooks into:

- `get_blob` / `head_blob` (`crates/nebula-registry/src/main.rs` —
  blob serving paths)
- `put_blob` / `complete_blob_upload`
- `get_manifest` / `put_manifest`
- pull-through cache miss vs. hit (already differentiated in
  `nebula-mirror`)
- 011 peer mesh hits (peer reports back to registry asynchronously)

Row shape:

```sql
(at, tenant, project, repository, op, bytes, src, status, ip, sub)
-- src: 'origin' | 'cache' | 'peer' | 'pull-through'
```

Hot writes go to an UNLOGGED staging table, drained every 60 s into
the durable `usage_events` table — keeps p99 push latency unaffected.

### 2. Continuous aggregation

A controller-managed task computes hourly + daily rollups via
straightforward `INSERT … SELECT` aggregates, populating
`usage_hourly` and `usage_daily`. Raw events kept 7 days then
truncated; rollups kept indefinitely (cardinality is bounded:
`(tenant, project, day)` ≈ thousands per year).

Cost projection:

```rust
// crates/nebula-cost/src/lib.rs
pub struct CostModel {
    pub egress_per_gb: f64,            // dollars
    pub storage_per_gb_month: f64,
    pub cache_egress_factor: f64,      // 1.0 = same as origin; 0.0 = free (peer hit)
}

impl CostModel {
    pub fn project(&self, h: &UsageHourly) -> Dollars { ... }
}
```

Cost models per backend (S3 us-east-1, GCS, Azure Blob, on-prem)
shipped as defaults in `nebulacr.toml`; operators override per
storage backend.

Quota enforcement: the existing `Tenant.spec.quotas` block has
`maxStorageBytes`, `pullRatePerMinute`, `pushRatePerMinute`. This
design wires those numbers to the rollup table — when a tenant
crosses 90 % a soft warning fires (webhook + dashboard banner);
at 100 % the request is rate-limited or rejected per quota policy.

CLI: `nebulacr usage tenant <name> --since 30d`,
`nebulacr usage project <ref> --by repository`,
`nebulacr cost report --month 2026-05 --format csv`. MCP:
`get_usage`, `get_cost_projection`.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: Tenant
spec:
  quotas:
    maxStorageBytes: 107374182400
    monthlyEgressBytes: 1099511627776   # NEW — 1 TiB/month
    pullRatePerMinute: 1000
    pushRatePerMinute: 500
  alerts:
    - kind: egress-anomaly             # NEW — z-score over 7d baseline
      threshold: 3.0
      webhookRef:
        name: tenant-slack
    - kind: budget
      thresholdDollars: 1000
      webhookRef:
        name: tenant-finance
```

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: CostModel
metadata:
  name: aws-us-east-1
spec:
  egressPerGb: 0.09
  storagePerGbMonth: 0.023
  cacheEgressFactor: 1.0
  scope:
    storageBackend: s3
    region: us-east-1
```

## d. New HTTP routes

| Method | Path                                                       | Auth scope         | Notes                                            |
| ------ | ---------------------------------------------------------- | ------------------ | ------------------------------------------------ |
| GET    | `/v2/_usage/tenant/{name}?since=1d&granularity=1h`         | `tenant:read`      | Time-series JSON                                 |
| GET    | `/v2/_usage/project/{ref}?since=30d&groupBy=repository`    | `tenant:read`      | Drilldown                                        |
| GET    | `/v2/_usage/top-pulled?since=7d&limit=20`                  | `tenant:read`      | Hottest images                                   |
| GET    | `/v2/_cost/report?tenant=acme&month=2026-05&format=csv`    | `tenant:admin`     | CSV / JSON / HTML                                 |
| GET    | `/v2/_cost/forecast?tenant=acme`                           | `tenant:read`      | Linear forecast for end of month                 |
| POST   | `/v2/_usage/anomalies/check`                               | system             | Internal — controller calls hourly              |

All endpoints honour tenant scoping: a tenant token can only see
its own; admin token sees cross-tenant.

## e. Storage / Postgres schema

```sql
-- 0017_usage.sql
CREATE UNLOGGED TABLE usage_events_staging (
    at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant     TEXT NOT NULL,
    project    TEXT NOT NULL,
    repository TEXT NOT NULL,
    op         TEXT NOT NULL,                       -- pull | push | manifest_get | manifest_put
    bytes      BIGINT NOT NULL,
    src        TEXT NOT NULL,                       -- origin | cache | peer | pull-through
    status     INT NOT NULL,                        -- HTTP status
    ip         INET,
    sub        TEXT
);
CREATE INDEX usage_events_staging_at_idx ON usage_events_staging (at);

CREATE TABLE usage_events (
    LIKE usage_events_staging INCLUDING ALL
);
-- Partition by day for fast truncation.
SELECT create_partition('usage_events', 'at', 'day', 7);  -- 7d retention

CREATE TABLE usage_hourly (
    bucket_at      TIMESTAMPTZ NOT NULL,
    tenant         TEXT NOT NULL,
    project        TEXT NOT NULL,
    repository     TEXT NOT NULL,
    op             TEXT NOT NULL,
    src            TEXT NOT NULL,
    bytes          BIGINT NOT NULL,
    requests       BIGINT NOT NULL,
    PRIMARY KEY (bucket_at, tenant, project, repository, op, src)
);
CREATE INDEX usage_hourly_tenant_idx ON usage_hourly (tenant, bucket_at DESC);

CREATE TABLE usage_daily (
    LIKE usage_hourly INCLUDING ALL
);

-- Anomaly baselines: rolling 7-day mean + stddev per (tenant, op).
CREATE TABLE usage_baselines (
    tenant         TEXT NOT NULL,
    op             TEXT NOT NULL,
    mean_bytes     DOUBLE PRECISION NOT NULL,
    stddev_bytes   DOUBLE PRECISION NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant, op)
);

CREATE TABLE cost_models (
    name           TEXT PRIMARY KEY,
    spec           JSONB NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

The staging-table pattern is the single biggest correctness lever
here: hot writes do NOT take the durable index hit on the request
path. Any usage row lost during a crash is bounded to the last 60 s
window — acceptable for billing-grade fidelity since the same
events are also exposed via Prometheus metrics for cross-checking.

## f. Failure modes

- **Drainer crashes during the rollup window.** On restart, the
  staging table is processed from `MIN(at)`; a `last_drained_at`
  cursor in `usage_baselines` ensures idempotent inserts (UNIQUE
  on `(bucket_at, tenant, project, repository, op, src)`).
- **Cost model out of date** (price changes mid-month). Cost rows
  carry the model `name` + `version`; rebuild a month by replaying
  rollups against new model.
- **Tenant exceeds quota mid-pull.** Rate-limit middleware reads
  the latest 1m bucket; over-quota → 429. The granularity is
  60 s so a quota burst can briefly leak — acceptable; alternative
  is sub-second checks which add too much hot-path cost.
- **Anomaly false positive.** Z-score threshold tunable; weekend /
  weekday seasonality handled by separate baselines per dow if
  operator turns it on.
- **Postgres ballooning.** Partitioned `usage_events` truncated
  daily; rollup tables are bounded; no TOAST hot rows.

## g. Migration story

`[usage] enabled = false`. Schema ships; the hooks are no-op
function pointers. Enabling pours data into `usage_events_staging`
from that moment on. The dashboard says "no data yet" until the
first hour rolls up. Cost reports show "$0" until at least one full
day of data + a configured cost model.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Drainer            | `crates/nebula-cost/tests/drain.rs`                    | 10k events → 60s window → assert drained    |
| Hourly rollup      | `crates/nebula-cost/tests/rollup.rs`                   | Postgres testcontainer; idempotent re-run   |
| Cost projection    | `crates/nebula-cost/tests/cost_model.rs`               | Known input → known dollars                 |
| Anomaly detector   | `crates/nebula-cost/tests/anomaly.rs`                  | Synthetic series → expected alert           |
| Quota enforcement  | `crates/nebula-registry/tests/quota_enforce.rs`        | 1k pulls → 429 at threshold                 |
| End-to-end         | `tests/e2e/usage_e2e.sh`                               | Push/pull churn → CSV report                |

## i. Implementation slice count

3 slices, ~3 weeks:

1. `usage_events` schema + drainer task + push-path / pull-path
   hook (no UI, no rollups yet — raw collection only).
2. Hourly + daily rollups + `_usage` endpoints + Tenant CRD quota
   enforcement.
3. Cost model + reports + anomaly detection + dashboard wiring
   (007) + CLI/MCP + docs.
