# Observability

NebulaCR ships an enterprise-grade observability bundle: Prometheus metrics across every layer (HTTP, storage, mirror, replication, webhooks, auth), structured JSON logs, OpenTelemetry tracing, six pre-built Grafana dashboards, and a PrometheusRule with SLO-style alerts.

The bundled artifacts live under [`deploy/observability/`](../deploy/observability/) and are wired up by `docker-compose.observability.yml` for local development; for Kubernetes use the chart's `serviceMonitor.enabled` and `prometheusRule.enabled` toggles.

## Table of Contents

- [One-command local stack](#one-command-local-stack)
- [Bundled Grafana dashboards](#bundled-grafana-dashboards)
- [Bundled alert rules](#bundled-alert-rules)
- [Metric reference](#metric-reference)
- [Structured JSON Logging](#structured-json-logging)
- [OpenTelemetry Tracing](#opentelemetry-tracing)
- [Health Endpoints](#health-endpoints)

## One-command local stack

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d
```

| Service     | URL                       | Login         |
|-------------|---------------------------|---------------|
| Registry    | http://localhost:5000     | -             |
| Auth        | http://localhost:5001     | -             |
| Prometheus  | http://localhost:9091     | -             |
| Grafana     | http://localhost:3000     | admin / admin |

Grafana auto-loads the dashboards from `deploy/observability/grafana/dashboards/` via provisioning. Prometheus auto-loads the alert rules from `deploy/observability/prometheus/rules/`.

## Bundled Grafana dashboards

| File | UID | Audience | What it shows |
|---|---|---|---|
| `nebulacr-overview.json` | `nebulacr-overview` | Ops on-call | Golden signals: request rate, error rate, p50/p95/p99 latency, push/pull throughput, in-flight requests, rate-limit rejections |
| `nebulacr-storage.json` | `nebulacr-storage` | Ops / SRE | Storage backend ops/sec, error rate, p95/p99 latency by op, retry attempts, circuit breaker state & transitions |
| `nebulacr-auth.json` | `nebulacr-auth` | Ops / SecOps | Token issuance, auth failures broken down by reason, OIDC outcomes by provider, robot/group activity, auth-route latency |
| `nebulacr-mirror.json` | `nebulacr-mirror` | Ops | Mirror cache miss rate, upstream request outcomes, p95 upstream latency, upstream circuit breakers, cache population bytes |
| `nebulacr-replication.json` | `nebulacr-replication` | Ops / Platform | Replication queue depth, lag by source region, success/error per region, region health, failover transitions, replication throughput |
| `nebulacr-tenants.json` | `nebulacr-tenants` | Developers / Tenants | Per-tenant push/pull bytes, top 10 tenants by usage, tenant rate-limit pressure, webhook delivery |
| `nebulacr-fleet.json` | `nebulacr-fleet` | Leadership / SLO | Availability SLO (24h non-5xx ratio), p99 latency SLO, active circuit breakers, error budget burn, uptime |

## Bundled alert rules

The Prometheus rule file at [`deploy/observability/prometheus/rules/nebulacr-alerts.yml`](../deploy/observability/prometheus/rules/nebulacr-alerts.yml) defines six rule groups:

| Group | Highlights |
|---|---|
| `nebulacr.availability` | `NebulaCRTargetDown`, `NebulaCRHigh5xxRate`, `NebulaCRP99LatencyHigh` |
| `nebulacr.storage` | `NebulaCRStorageErrorRate`, `NebulaCRStorageP99Slow`, `NebulaCRCircuitBreakerOpen`, `NebulaCRRetryStorm` |
| `nebulacr.mirror` | `NebulaCRMirrorUpstreamErrors`, `NebulaCRMirrorCacheHitRatioLow` |
| `nebulacr.replication` | `NebulaCRReplicationLag`, `NebulaCRReplicationQueueBacklog`, `NebulaCRReplicationFailures`, `NebulaCRRegionUnhealthy` |
| `nebulacr.auth` | `NebulaCRAuthFailureSpike`, `NebulaCRTokenIssuanceStopped` |
| `nebulacr.webhook` | `NebulaCRWebhookDeliveryFailing` |

The same rules ship as a Helm `PrometheusRule` template. Enable in `values.yaml`:

```yaml
prometheusRule:
  enabled: true
  thresholds:
    http5xxRatio: 0.05
    httpP99LatencySeconds: 2
    storageP99LatencySeconds: 5
    replicationLagSeconds: 300
```

---

## Metric reference

NebulaCR exposes Prometheus metrics from both services on `/metrics`. The registry can also bind a dedicated `metrics_addr` (default `:9090`) for out-of-band scraping. All new instrumentation uses the `nebulacr_*` namespace; the legacy per-operation counters keep the `registry_*` prefix for backwards compatibility with older dashboards.

### HTTP / Service-level (registry + auth)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_http_requests_total` | Counter | `route`, `method`, `status_class` | Registry HTTP requests, route is a low-cardinality classifier (manifest_get, blob_get, blob_upload_chunk, …) |
| `nebulacr_http_request_duration_seconds` | Histogram | `route`, `method` | Registry HTTP request latency |
| `nebulacr_http_requests_in_flight` | Gauge | `route` | Currently in-flight registry requests |
| `nebulacr_auth_http_requests_total` | Counter | `route`, `method`, `status_class` | Auth-service HTTP requests |
| `nebulacr_auth_http_request_duration_seconds` | Histogram | `route`, `method` | Auth-service HTTP request latency |
| `nebulacr_auth_http_requests_in_flight` | Gauge | `route` | In-flight auth-service requests |
| `nebulacr_rate_limit_rejected_total` | Counter | `tenant` | Requests rejected by the registry rate limiter |
| `nebulacr_build_info` | Gauge | `service`, `version`, `rustc` | Static `1` series; labels carry build metadata |
| `nebulacr_process_start_time_seconds` | Gauge | – | Wall-time the process started (for uptime calculations) |

### Storage backend (resilience layer)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_storage_operations_total` | Counter | `operation`, `outcome` | All `ObjectStore` operations through the resilient wrapper |
| `nebulacr_storage_operation_errors_total` | Counter | `operation` | Subset of the above where `outcome="error"` |
| `nebulacr_storage_operation_duration_seconds` | Histogram | `operation` | End-to-end latency for each storage op |
| `nebulacr_retry_attempts_total` | Counter | `operation`, `outcome` (`recovered`, `exhausted`) | Retry attempts emitted by the retry policy |
| `nebulacr_circuit_breaker_state` | Gauge | `breaker` | 0 = closed, 1 = half-open, 2 = open |
| `nebulacr_circuit_breaker_transitions_total` | Counter | `breaker`, `to` | Transitions counted per target state |
| `nebulacr_circuit_breaker_rejections_total` | Counter | `breaker` | Calls short-circuited because the breaker was open |

The `breaker` label is `storage` for the resilient object store wrapper, `upstream-<name>` for each mirror upstream, and `replication-<region>` for each replication peer.

### Mirror / pull-through cache

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_mirror_cache_misses_total` | Counter | `kind` (`manifest`, `blob`) | Local lookup missed and we contacted an upstream |
| `nebulacr_mirror_fetch_total` | Counter | `kind`, `outcome` (`fetched`, `not_found`, `error`, `skipped_scope`, `skipped_unlinked`, `no_upstreams`) | Final result of a mirror fetch |
| `nebulacr_mirror_cache_population_bytes_total` | Counter | `kind`, `upstream` | Bytes cached locally after upstream fetch |
| `nebulacr_mirror_upstream_requests_total` | Counter | `upstream`, `kind`, `outcome` (`success`, `not_found`, `auth_error`, `upstream_5xx`, `breaker_open`, `error`) | Per-upstream result of a single fetch attempt |
| `nebulacr_mirror_upstream_latency_seconds` | Histogram | `upstream`, `kind` | Upstream HTTP latency |
| `nebulacr_mirror_upstream_bytes_total` | Counter | `upstream`, `kind` | Bytes fetched from upstream |

### Multi-region replication

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_replication_enqueued_total` | Counter | `kind` | Replication events enqueued by request handlers |
| `nebulacr_replication_enqueue_failures_total` | Counter | – | Channel-send failures during enqueue |
| `nebulacr_replication_queue_depth` | Gauge | – | Live depth of the bounded MPSC channel |
| `nebulacr_replication_lag_seconds` | Gauge | `source_region` | Wall-time between event creation and the replicator dequeueing it |
| `nebulacr_replication_events_total` | Counter | `region`, `kind`, `outcome` | Per-region replication attempts |
| `nebulacr_replication_event_duration_seconds` | Histogram | `region`, `kind` | Per-region replication latency |
| `nebulacr_replication_bytes_total` | Counter | `region`, `kind` | Bytes successfully replicated |
| `nebulacr_region_healthy` | Gauge | `region` | 1 = healthy, 0 = unhealthy (failover manager) |
| `nebulacr_region_health_check_latency_seconds` | Gauge | `region` | Latency of the most recent health probe |
| `nebulacr_region_health_transitions_total` | Counter | `region`, `to` | Health state transitions per region |

### Webhook notifier

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_webhook_enqueued_total` | Counter | `event` | Events handed to the notifier |
| `nebulacr_webhook_enqueue_failures_total` | Counter | `event` | Channel-send failures |
| `nebulacr_webhook_delivery_attempts_total` | Counter | `endpoint`, `outcome` (`non_success_status`, `transport_error`) | Individual delivery attempts that failed |
| `nebulacr_webhook_deliveries_total` | Counter | `endpoint`, `event`, `outcome` (`success`, `failed`) | Final delivery outcome per event |
| `nebulacr_webhook_delivery_duration_seconds` | Histogram | `endpoint`, `event` | End-to-end delivery latency |

### Auth (existing `registry_*` series, kept for compatibility)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `registry_auth_requests_total` | Counter | – | Total token requests |
| `registry_token_issued_total` | Counter | – | Tokens issued |
| `registry_auth_failures_total` | Counter | `reason` | Auth failures broken down by reason |
| `registry_oidc_logins_total` | Counter | `provider`, `status` | OIDC login attempts |
| `registry_robot_auth_total` | Counter | `robot` | Robot account auths |
| `registry_group_mapping_hits_total` | Counter | `group` | Group mapping resolutions |
| `registry_token_refresh_total` | Counter | – | Token refreshes |
| `registry_token_revocation_total` | Counter | – | Token revocations |
| `registry_scim_provisions_total` | Counter | `action` | SCIM provisioning operations |

### Registry per-operation totals (`registry_*`, kept for compatibility)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `registry_manifest_push_total` | Counter | – | Manifest pushes |
| `registry_manifest_pull_total` | Counter | – | Manifest pulls |
| `registry_blob_pull_total` | Counter | – | Blob pulls |
| `registry_pull_total` | Counter | `tenant`, `project` | Per-tenant pulls |
| `registry_delete_total` | Counter | `tenant`, `project` | Per-tenant deletes |
| `registry_blob_upload_bytes_total` | Counter | `tenant` | Per-tenant push bytes |
| `registry_push_bytes_total` | Counter | – | Total push bytes |
| `registry_pull_bytes_total` | Counter | – | Total pull bytes |
| `registry_request_duration_seconds` | Histogram | `operation` | Per-operation latency |
| `registry_errors_total` | Counter | `type` | High-level error classifier |

### Configuration

```toml
[server]
metrics_addr = "0.0.0.0:9090"
```

```bash
NEBULACR_SERVER__METRICS_ADDR=0.0.0.0:9090
```

### Kubernetes ServiceMonitor & PrometheusRule

If you run prometheus-operator, enable the bundled CRDs in `values.yaml`:

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: prometheus  # match your prometheus-operator selector

prometheusRule:
  enabled: true
```

The chart ships both a `ServiceMonitor` and a `PrometheusRule` with the same alerts as the local-stack file. Override per-alert thresholds via `prometheusRule.thresholds` without forking the chart.

### Static scrape config (no operator)

```yaml
scrape_configs:
  - job_name: nebulacr-registry
    metrics_path: /metrics
    static_configs:
      - targets: ["nebulacr-registry.nebulacr.svc.cluster.local:5000"]

  - job_name: nebulacr-auth
    metrics_path: /metrics
    static_configs:
      - targets: ["nebulacr-auth.nebulacr.svc.cluster.local:5001"]
```

---

## Structured JSON Logging

NebulaCR uses the `tracing` framework with structured JSON output recommended for production.

### Configuration

```toml
[observability]
log_level = "info"
log_format = "json"
```

```bash
# Using the tracing env-filter syntax
RUST_LOG="info,nebula_registry=debug,nebula_common=debug"

# Or via NebulaCR config
NEBULACR_OBSERVABILITY__LOG_LEVEL=info
NEBULACR_OBSERVABILITY__LOG_FORMAT=json
```

### Log Format

JSON log output looks like this:

```json
{
  "timestamp": "2025-01-15T10:30:00.123456Z",
  "level": "INFO",
  "target": "nebula_registry::routes",
  "message": "manifest pushed",
  "span": {
    "name": "push_manifest",
    "tenant": "acme",
    "project": "backend",
    "repository": "api-server",
    "tag": "v1.2.3"
  },
  "fields": {
    "digest": "sha256:abc123...",
    "content_type": "application/vnd.oci.image.manifest.v1+json",
    "duration_ms": 42
  }
}
```

### Log Level Reference

| Level | Use |
|-------|-----|
| `error` | Unrecoverable failures, storage errors, auth failures |
| `warn` | Recoverable issues, rate limit hits, circuit breaker state changes |
| `info` | Normal operations: pushes, pulls, token issuance, startup |
| `debug` | Detailed request/response data, storage operations, auth flow |
| `trace` | Very verbose per-byte data, JWT parsing, header inspection |

### Filtering by Component

The `RUST_LOG` variable supports per-crate filters:

```bash
# Debug for registry, info for everything else
RUST_LOG="info,nebula_registry=debug"

# Debug for auth, warn for everything else
RUST_LOG="warn,nebula_auth=debug"

# Trace storage operations
RUST_LOG="info,nebula_common::storage=trace"

# Debug all NebulaCR crates
RUST_LOG="info,nebula_registry=debug,nebula_auth=debug,nebula_common=debug"
```

### Pretty Logging (Development)

For local development, use the human-readable format:

```bash
NEBULACR_OBSERVABILITY__LOG_FORMAT=pretty
```

---

## OpenTelemetry Tracing

NebulaCR supports distributed tracing via the OpenTelemetry Protocol (OTLP). Traces are exported to any OTLP-compatible collector (Jaeger, Grafana Tempo, Datadog, etc.).

### Configuration

```toml
[observability]
otlp_endpoint = "http://otel-collector:4317"
```

```bash
NEBULACR_OBSERVABILITY__OTLP_ENDPOINT=http://otel-collector:4317
```

### Helm Values

```yaml
observability:
  otlpEndpoint: "http://otel-collector.monitoring.svc.cluster.local:4317"
  tracing:
    enabled: true
    samplingRatio: 0.1   # Sample 10% of requests
```

### Supported Backends

| Backend | OTLP Endpoint Example |
|---------|----------------------|
| OpenTelemetry Collector | `http://otel-collector:4317` (gRPC) |
| Grafana Tempo | `http://tempo:4317` (gRPC) |
| Jaeger | `http://jaeger:4317` (gRPC) |
| Datadog Agent | `http://datadog-agent:4317` (with OTLP ingest) |

### Trace Context

NebulaCR propagates trace context via the W3C `traceparent` header. Traces span across the auth and registry services when both are configured with the same collector.

A typical push trace includes spans for:

1. HTTP request handling
2. Token validation
3. Storage backend write (blob or manifest)
4. Rate limit check
5. Webhook dispatch (if configured)

### Example: Grafana Tempo with Docker Compose

Add a Tempo service to your `docker-compose.yml`:

```yaml
services:
  tempo:
    image: grafana/tempo:latest
    command: ["-config.file=/etc/tempo.yaml"]
    ports:
      - "3200:3200"   # Tempo API
      - "4317:4317"   # OTLP gRPC
    volumes:
      - ./tempo.yaml:/etc/tempo.yaml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_AUTH_ANONYMOUS_ENABLED: "true"
      GF_AUTH_ANONYMOUS_ORG_ROLE: Admin
```

Then add to the registry and auth services:

```yaml
environment:
  NEBULACR_OBSERVABILITY__OTLP_ENDPOINT: "http://tempo:4317"
```

---

## Grafana dashboards

The bundled JSON dashboards listed at the top of this doc cover every layer of the system. They live under `deploy/observability/grafana/dashboards/` and are auto-loaded by the local stack. To import them into an external Grafana, paste any of the JSON files via *Dashboards → Import*.

---

## Health Endpoints

NebulaCR exposes health check endpoints on both services.

### Registry Health

```bash
# Liveness check
curl -f http://localhost:5000/health
# Response: 200 OK

# OCI Distribution specification endpoint (also serves as readiness check)
curl -f http://localhost:5000/v2/
# Response: 200 OK (if authenticated) or 401 Unauthorized (expected without token)
```

### Auth Health

```bash
curl -f http://localhost:5001/health
# Response: 200 OK
```

### Kubernetes Probes

The Helm chart configures liveness and readiness probes automatically. The docker-compose file includes equivalent healthchecks:

```yaml
# Registry healthcheck (from docker-compose.yml)
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
  interval: 15s
  timeout: 5s
  retries: 5
  start_period: 10s

# Auth healthcheck
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:5001/health"]
  interval: 10s
  timeout: 5s
  retries: 10
  start_period: 30s
```

### Metrics Endpoint

The metrics endpoint itself can be used as a health indicator:

```bash
curl -f http://localhost:9090/metrics
# Returns Prometheus exposition format
```

This endpoint is served on a separate port (9090 for registry, 9091 for auth in Helm) and should only be accessible from within the cluster or monitoring infrastructure.
