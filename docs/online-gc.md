# Online Garbage Collection

NebulaCR's online GC keeps the registry from accumulating dead blobs without
requiring a read-only window. Every manifest push records blob edges in
Postgres, and a continuous reaper drains zero-refcount blobs once they sit
past a configurable grace period.

This is opt-in; existing deployments are unaffected when GC is disabled.

## When to enable

Turn it on once Postgres is in the picture (i.e. the scanner is enabled, or
you've supplied `gc.online.postgresUrl` directly). Without GC the registry
grows monotonically — fine for ephemeral testing, painful in production.

## Helm

```yaml
gc:
  online:
    enabled: true
    reaper:
      enabled: true        # spawn the continuous reaper
      graceSecs: 86400     # how long a blob must sit at refcount=0
      batch: 200           # rows reaped per cycle
      idleSleepSecs: 30
      qps: 100             # storage delete cap
```

## Environment variables (raw)

| Variable                              | Default | Notes                                                  |
| ------------------------------------- | ------- | ------------------------------------------------------ |
| `NEBULACR_GC__ONLINE`                 | `false` | Master switch                                          |
| `NEBULACR_GC__POSTGRES_URL`           | (none)  | Required if scanner is disabled                        |
| `NEBULACR_GC__REAPER_ENABLED`         | `true`  | Set to `false` to refcount-only (run reap from CronJob)|
| `NEBULACR_GC__REAPER_GRACE_SECS`      | `86400` | Worst-case upload duration ceiling                     |
| `NEBULACR_GC__REAPER_BATCH`           | `200`   | Rows per drain cycle                                   |
| `NEBULACR_GC__REAPER_IDLE_SLEEP_SECS` | `30`    | Sleep between empty cycles                             |
| `NEBULACR_GC__REAPER_QPS`             | `100`   | Storage delete operations per second                   |

## HTTP control plane (admin role required)

| Method | Path                  | Notes                                                |
| ------ | --------------------- | ---------------------------------------------------- |
| GET    | `/v2/_gc/status`      | `{enabled, paused, stopped}`                         |
| POST   | `/v2/_gc/pause`       | Pause the reaper                                     |
| POST   | `/v2/_gc/resume`      | Resume                                               |
| POST   | `/v2/_gc/reconcile`   | Body `{apply: bool, max?: int}` — drift detection    |

## How it works

```
push    → manifest_blob_refs += edges
        → blob_refcounts.refcount += 1
        → blob_paths += (tenant, project, repo, digest)
delete  → manifest_blob_refs -= edges
        → blob_refcounts.refcount -= 1 (zeroed_at = NOW() if it hit 0)
reaper  → SELECT zero-refcount rows older than grace, FOR UPDATE SKIP LOCKED
        → delete every storage object recorded in blob_paths
        → drop bookkeeping rows + write gc_reaps
```

`FOR UPDATE SKIP LOCKED` lets multiple registry pods reap concurrently
without duplicate work. The token bucket caps storage delete operations per
second; if S3 returns 429, the reaper slows itself rather than failing
manifest pushes.

## Drift detection

The reconciler walks `manifest_blob_refs` to recompute expected refcounts
and compares against `blob_refcounts`. Three classifications:

- **`missing`** — edges exist, no refcount row → fix creates the row.
- **`orphan`** — refcount > 0 but no edges → fix flips refcount to 0 so
  the next reaper cycle picks it up.
- **`underflow`** — observed > expected → fix resets observed to expected.

Drift rows go to `gc_drift`; an operator runs `POST /v2/_gc/reconcile
{"apply": true}` to correct.

## Operational guidance

- **Start with audit-only.** Run `POST /v2/_gc/reconcile` regularly with
  `apply: false` for the first week. If `gc_drift` stays empty you can
  schedule daily `apply: true` cycles.
- **Watch `gc_reaps` row count over time.** Reap rate going to zero
  unexpectedly usually means the storage backend started rate-limiting —
  check registry logs for repeated `online-gc reap failed` warnings.
- **Bigger registries need a longer grace period.** The grace must be
  longer than your longest acceptable upload duration. Default is 24h —
  safe for normal CI but conservative.
- **Pause during incidents.** `POST /v2/_gc/pause` is idempotent and
  cooperatively stops the reaper at the next cycle without touching
  in-flight deletes.

## Smoke test

```bash
GRACE=5 bash tests/e2e/online_gc_e2e.sh
```

Pushes an image, deletes it, waits past the grace, and asserts the reaper
deleted the storage object + wrote a `gc_reaps` row + the reconciler is
clean.
