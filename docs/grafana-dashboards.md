# Grafana Dashboards

NebulaCR ships two Grafana dashboards aimed at enterprise operators
and decision-makers:

| Dashboard                | UID                | Audience              |
| ------------------------ | ------------------ | --------------------- |
| **Enterprise Overview**  | `nebulacr-overview`| Execs, finance, security leads |
| **Operations Detail**    | `nebulacr-detail`  | SREs, platform engineers |

Both are version-controlled JSON in `deploy/helm/nebulacr/dashboards/`
and render through the Helm chart as `grafana_dashboard`-labelled
ConfigMaps so the [kube-prometheus-stack][kps] / [grafana-helm][gh]
sidecar auto-loads them.

[kps]: https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack
[gh]:  https://github.com/grafana/helm-charts/tree/main/charts/grafana

## What you get

### Overview (`nebulacr-overview`)

Top stat row:

| Metric                       | Source                | Threshold colours       |
| ---------------------------- | --------------------- | ----------------------- |
| Total images                 | `manifest_blob_refs`  | none                    |
| Total storage                | `blob_refcounts`      | yellow > 1 TiB, red > 5 TiB |
| Average image size           | `manifest_blob_refs` × `blob_refcounts` | yellow > 500 MiB, red > 2 GiB |
| Projected monthly cost (USD) | `usage_daily` + `cost_models` | yellow > $500, red > $5 000 |
| Open Critical+High CVEs      | `findings` − `suppressions` | yellow ≥ 1, red ≥ 10 |
| Mirror cache hit ratio       | `nebulacr_mirror_*` Prometheus | yellow < 85 %, red < 50 % |

Plus stacked storage- and egress-trend timeseries for the last 30 days,
and two top-10 tables: "tenants by storage / cost" and "tenants by
CVE exposure".

### Detail (`nebulacr-detail`)

Six rows:

1. **Image size** — distribution histogram + top-20 too-large outliers.
2. **Request volume** — per-op rate (pull / push / manifest / delete) +
   p50/p95/p99 latency.
3. **Mirror & GC** — pull-through hit/miss split, upstream bytes,
   GC reaper hourly rate.
4. **Scanning** — findings broken down by `(detector, severity)`,
   top-20 images by Critical CVEs.
5. **Health** — scan queue depth + 5xx rate per route.

Both dashboards filter by the `tenant` template variable (multi-select
+ "All").

## Required datasources

Each dashboard takes two datasources via template variables:

- `datasource_prom` — a Prometheus instance scraping the registry's
  `/metrics` (the chart's `serviceMonitor.enabled=true` covers this).
- `datasource_pg`   — a PostgreSQL datasource pointing at the same
  database the registry / scanner / GC writes to.

The Postgres datasource needs **read-only** access to:

- `manifest_blob_refs`, `blob_refcounts`, `gc_reaps`, `gc_drift`
- `usage_daily`, `usage_hourly`, `cost_models`
- `scans`, `scan_jobs`, `findings`, `suppressions`
- `tags`

A dedicated read-only role:

```sql
CREATE ROLE grafana_ro LOGIN PASSWORD '<...>';
GRANT CONNECT ON DATABASE nebulacr TO grafana_ro;
GRANT USAGE ON SCHEMA public TO grafana_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON TABLES TO grafana_ro;
```

## Installing

### Default — alongside kube-prometheus-stack

```yaml
# values.yaml for the parent chart / the nebulacr release
grafana:
  dashboards:
    enabled: true
```

When the standard kube-prometheus-stack Grafana sidecar is configured
to scan the namespace (`grafana.sidecar.dashboards.searchNamespace:
ALL` is the easiest mode), the dashboards appear in the **NebulaCR**
folder within ~30s of `helm upgrade`.

### Custom Grafana

If you run Grafana with a different sidecar (`kiwigrid/k8s-sidecar`)
override the discovery label:

```yaml
grafana:
  dashboards:
    enabled: true
    discoveryLabel: my-grafana-dashboard
```

### Without the sidecar (manual import)

Both JSON files live at `deploy/helm/nebulacr/dashboards/*.json` and
import cleanly into Grafana via **Dashboards → Import**.

## Cost-projection details

The "Projected monthly cost" stat and "Top tenants by cost" table use
the `cost_models` table populated by 017's CostModel. When no model is
configured the panels fall back to AWS us-east-1 defaults
($0.09/GB egress + $0.023/GB-month storage). Add a model:

```sql
INSERT INTO cost_models (name, spec) VALUES (
  'aws-eu-west-2',
  '{
     "egress_per_gb": 0.09,
     "storage_per_gb_month": 0.025,
     "cache_egress_factor": 0.0
   }'::jsonb
)
ON CONFLICT (name) DO UPDATE SET spec = EXCLUDED.spec, updated_at = NOW();
```

## Suppressions / scope

The Critical+High panels honour the `suppressions` table — a CVE that
is suppressed (and not revoked / not expired) doesn't count toward the
exposure metric. Operators see what they should be acting on, not the
full historical record.

## Customising

Dashboards are just JSON. Edit
`deploy/helm/nebulacr/dashboards/nebulacr-{overview,detail}.json`
locally, run `python3 -m json.tool ... > /dev/null` to validate, then
`helm upgrade` — the sidecar reloads the new payload.

If you want to add a panel that joins, say, `peer_stats_hourly`
(peer-mesh hit ratios) or `attestations` (SLSA-level distribution),
both tables are documented in `docs/design/` and indexed for the kinds
of queries Grafana writes.
