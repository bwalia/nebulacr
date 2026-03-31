# Observability

NebulaCR provides Prometheus metrics, structured JSON logging, and OpenTelemetry distributed tracing. This guide covers how to configure, collect, and visualize operational data from the registry.

## Table of Contents

- [Prometheus Metrics](#prometheus-metrics)
- [Structured JSON Logging](#structured-json-logging)
- [OpenTelemetry Tracing](#opentelemetry-tracing)
- [Grafana Dashboard Suggestions](#grafana-dashboard-suggestions)
- [Health Endpoints](#health-endpoints)

---

## Prometheus Metrics

NebulaCR exposes Prometheus metrics on a dedicated port (default: 9090) separate from the main API. This port should not be exposed to the public internet.

### Configuration

```toml
[server]
metrics_addr = "0.0.0.0:9090"
```

```bash
NEBULACR_SERVER__METRICS_ADDR=0.0.0.0:9090
```

### Key Metrics

#### Registry Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_http_requests_total` | Counter | `method`, `path`, `status` | Total HTTP requests handled |
| `nebulacr_http_request_duration_seconds` | Histogram | `method`, `path` | Request latency distribution |
| `nebulacr_blob_upload_bytes_total` | Counter | `tenant` | Total bytes uploaded (blobs) |
| `nebulacr_blob_download_bytes_total` | Counter | `tenant` | Total bytes downloaded (blobs) |
| `nebulacr_manifest_push_total` | Counter | `tenant`, `project` | Total manifest pushes |
| `nebulacr_manifest_pull_total` | Counter | `tenant`, `project` | Total manifest pulls |
| `nebulacr_storage_operation_duration_seconds` | Histogram | `operation`, `backend` | Storage backend latency |
| `nebulacr_storage_operation_errors_total` | Counter | `operation`, `backend` | Storage backend errors |

#### Auth Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_token_issued_total` | Counter | `tenant`, `grant_type` | Total tokens issued |
| `nebulacr_token_rejected_total` | Counter | `reason` | Total token requests rejected |
| `nebulacr_auth_latency_seconds` | Histogram | `provider` | Authentication latency |

#### Rate Limiting Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_rate_limit_rejected_total` | Counter | `tenant`, `endpoint` | Requests rejected by rate limiter |
| `nebulacr_rate_limit_remaining` | Gauge | `tenant` | Remaining requests in current window |

#### Mirror / Pull-Through Cache Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_mirror_cache_hits_total` | Counter | `upstream` | Cache hits (served locally) |
| `nebulacr_mirror_cache_misses_total` | Counter | `upstream` | Cache misses (fetched from upstream) |
| `nebulacr_mirror_upstream_latency_seconds` | Histogram | `upstream` | Upstream fetch latency |
| `nebulacr_mirror_upstream_errors_total` | Counter | `upstream` | Upstream fetch errors |

#### Replication Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_replication_lag_seconds` | Gauge | `region` | Current replication lag |
| `nebulacr_replication_objects_synced_total` | Counter | `region` | Objects replicated |
| `nebulacr_replication_errors_total` | Counter | `region` | Replication errors |

#### Resilience Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_circuit_breaker_state` | Gauge | `backend` | Circuit breaker state (0=closed, 1=half-open, 2=open) |
| `nebulacr_retry_attempts_total` | Counter | `backend`, `outcome` | Storage retry attempts |

#### Tenant Quota Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nebulacr_tenant_storage_bytes` | Gauge | `tenant` | Current storage usage per tenant |
| `nebulacr_tenant_repository_count` | Gauge | `tenant` | Current repository count per tenant |
| `nebulacr_tenant_project_count` | Gauge | `tenant` | Current project count per tenant |

### Kubernetes ServiceMonitor

If you are running Prometheus Operator, enable the ServiceMonitor in your Helm values:

```yaml
serviceMonitor:
  enabled: true
  namespace: ""         # Defaults to release namespace
  interval: 30s
  scrapeTimeout: 10s
  labels:
    release: prometheus  # Match your Prometheus Operator selector
  metricRelabelings: []
  relabelings: []
```

### Static Prometheus Scrape Config

If you are not using the Prometheus Operator, add a scrape config to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "nebulacr-registry"
    metrics_path: /metrics
    static_targets:
      - targets:
          - "nebulacr-registry.nebulacr.svc.cluster.local:9090"
    scrape_interval: 30s

  - job_name: "nebulacr-auth"
    metrics_path: /metrics
    static_targets:
      - targets:
          - "nebulacr-auth.nebulacr.svc.cluster.local:9091"
    scrape_interval: 30s
```

For Kubernetes service discovery:

```yaml
scrape_configs:
  - job_name: "nebulacr"
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: nebulacr.*
        action: keep
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        target_label: __address__
        regex: (.+)
        replacement: "${1}"
```

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: nebulacr
    rules:
      - alert: NebulaCRHighErrorRate
        expr: |
          sum(rate(nebulacr_http_requests_total{status=~"5.."}[5m]))
          / sum(rate(nebulacr_http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "NebulaCR error rate above 5%"

      - alert: NebulaCRStorageErrors
        expr: rate(nebulacr_storage_operation_errors_total[5m]) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "NebulaCR storage backend errors detected"

      - alert: NebulaCRCircuitBreakerOpen
        expr: nebulacr_circuit_breaker_state == 2
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "NebulaCR circuit breaker is open for {{ $labels.backend }}"

      - alert: NebulaCRReplicationLag
        expr: nebulacr_replication_lag_seconds > 120
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "NebulaCR replication lag exceeds 2 minutes for {{ $labels.region }}"

      - alert: NebulaCRTenantStorageQuota
        expr: |
          nebulacr_tenant_storage_bytes / on(tenant) nebulacr_tenant_storage_quota_bytes > 0.9
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Tenant {{ $labels.tenant }} storage usage above 90%"
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

## Grafana Dashboard Suggestions

### Registry Overview Dashboard

Panels to include:

1. **Request Rate** - `sum(rate(nebulacr_http_requests_total[5m])) by (method)`
2. **Error Rate** - `sum(rate(nebulacr_http_requests_total{status=~"5.."}[5m]))`
3. **Request Latency (p50/p95/p99)** - `histogram_quantile(0.99, rate(nebulacr_http_request_duration_seconds_bucket[5m]))`
4. **Push/Pull Rate** - `rate(nebulacr_manifest_push_total[5m])` and `rate(nebulacr_manifest_pull_total[5m])`
5. **Bandwidth** - `rate(nebulacr_blob_upload_bytes_total[5m])` and `rate(nebulacr_blob_download_bytes_total[5m])`
6. **Active Tenants** - Unique tenant labels seen in recent metrics

### Storage Dashboard

1. **Storage Latency** - `histogram_quantile(0.95, rate(nebulacr_storage_operation_duration_seconds_bucket[5m]))`
2. **Storage Error Rate** - `rate(nebulacr_storage_operation_errors_total[5m])`
3. **Circuit Breaker State** - `nebulacr_circuit_breaker_state`
4. **Retry Rate** - `rate(nebulacr_retry_attempts_total[5m])`
5. **Per-Tenant Storage Usage** - `nebulacr_tenant_storage_bytes`

### Auth Dashboard

1. **Token Issuance Rate** - `rate(nebulacr_token_issued_total[5m])`
2. **Token Rejection Rate** - `rate(nebulacr_token_rejected_total[5m]) by (reason)`
3. **Auth Latency by Provider** - `histogram_quantile(0.95, rate(nebulacr_auth_latency_seconds_bucket[5m])) by (provider)`
4. **Rate Limit Rejections** - `rate(nebulacr_rate_limit_rejected_total[5m]) by (tenant)`

### Mirror / Cache Dashboard

1. **Cache Hit Ratio** - `sum(rate(nebulacr_mirror_cache_hits_total[5m])) / (sum(rate(nebulacr_mirror_cache_hits_total[5m])) + sum(rate(nebulacr_mirror_cache_misses_total[5m])))`
2. **Upstream Latency** - `histogram_quantile(0.95, rate(nebulacr_mirror_upstream_latency_seconds_bucket[5m])) by (upstream)`
3. **Upstream Errors** - `rate(nebulacr_mirror_upstream_errors_total[5m]) by (upstream)`

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
