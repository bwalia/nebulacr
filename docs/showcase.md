# NebulaCR Showcase — Article + Video Script

A 5-minute demo that takes a viewer from `docker push` to "here's
what your fleet looks like in Grafana." The end goal is to be the
visible artifact for the NebulaCR launch article + a short video
walkthrough.

## TL;DR

```
Build → docker push → CVE scan → docker pull → dashboard
```

Every step is covered by `.github/workflows/nebulacr-showcase.yml`
so anyone can fork the repo, set five secrets, and produce a green
run with real findings. The run summary tab links to the live
[Enterprise Overview](#dashboards) and [Operations Detail](#dashboards)
dashboards for the wider fleet view.

## Setup (~5 minutes)

You need a NebulaCR instance reachable from GitHub Actions. Either:

- **Use the public demo**: `demo.nebulacr.org` already has a `demo`
  tenant + `showcase` project pre-provisioned. Skip the host /
  tenant secrets; the workflow defaults match.
- **Run your own**: install via the Helm chart, expose the registry
  via Ingress, optionally enable `grafana.dashboards.enabled=true`.

Then add these repository secrets:

| Secret               | Purpose                                          |
| -------------------- | ------------------------------------------------ |
| `NEBULACR_USERNAME`  | Push credential                                   |
| `NEBULACR_PASSWORD`  | Push credential                                   |
| `NEBULACR_HOST`      | (optional, defaults to `demo.nebulacr.org`)      |
| `NEBULACR_TENANT`    | (optional, defaults to `demo`)                   |
| `NEBULACR_PROJECT`   | (optional, defaults to `showcase`)               |
| `GRAFANA_BASE`       | (optional, defaults to `https://grafana.demo.nebulacr.org`) |

## Running it

GitHub → Actions → **NebulaCR Showcase** → Run workflow. Default
inputs work. The run takes ~2 minutes end to end and produces the
summary card below.

## What the run shows

```
| Stage  | Result                                              |
| ------ | --------------------------------------------------- |
| Build  | ✅ demo.nebulacr.org/demo/showcase/showcase-app:42  |
| Push   | ✅ digest sha256:abcd…                              |
| Scan   | critical=2 high=14 medium=23 low=8                  |
| Policy | FAIL                                                |
| Pull   | ✅ round-trip OK                                    |
```

Plus dashboard links pre-filtered by `?var-tenant=demo`.

## Article outline (~800 words)

1. **Problem opener** (~100 words). The container-registry market
   has nice options for "store images" but no good open-source
   answer for "see your fleet end-to-end." Showing a dashboard with
   real signal lands the point fast.

2. **What NebulaCR is** (~150 words). Single-binary OCI Distribution
   v2 + scanner + GC + cost telemetry. List the three or four
   features that matter for the article (online GC with no read-only
   window, multi-detector scanning, per-tenant cost projection,
   pull-through cache).

3. **The five-step demo** (~300 words). Walk through the workflow
   stage by stage. Each stage includes a screenshot from the run
   summary or the dashboard.

   - Build → `docker build` (boring, fast).
   - Push → `docker push`. Same UX as Docker Hub.
   - Scan → highlight the live `/v2/scan/live/<digest>` poll. Show
     the JSON payload in a code block.
   - Pull → round-trip proves storage is real.
   - Dashboard → screenshot the Enterprise Overview with the
     freshly-pushed image visible in the "Top tenants by CVE
     exposure" table.

4. **What "production-ready" looks like** (~150 words). Pull from
   the slice 2/3 work in 009-019: continuous GC reaper that doesn't
   need a maintenance window; license / secret / malware detectors
   alongside CVE; SLSA attestation upload; auto-rebuild on base
   CVE patch. Reference `docs/design/` for depth.

5. **Try it** (~100 words). Fork → secrets → click. Link the
   workflow file directly.

## Video script (~3 minutes)

Use a screen-recording tool (OBS / QuickTime). Three segments:

### 0:00 — Setup (30s)
- Show the GitHub repo.
- "Five secrets, one click." Walk through pasting the secrets in
  the repo settings.

### 0:30 — Trigger + walkthrough (90s)
- Click "Run workflow" with defaults.
- While it runs, narrate over the YAML:
  - "Build is just a normal Dockerfile."
  - "Push uses the standard `docker login`/`docker push` flow —
    no proprietary client."
  - "After push, the registry's scanner enqueues a job; we poll
    `/v2/scan/live/<digest>` for completion."
  - "Then we pull it back to prove the round-trip."

### 2:00 — Result (60s)
- Show the run summary card with critical/high counts.
- Click the **Enterprise Overview** dashboard link.
- Pan over the panels: total storage, projected monthly cost,
  the freshly-pushed image showing up in "Top tenants by CVE
  exposure."
- Click through to **Operations Detail** — show image-size
  distribution + the GC reaper rate ticking down as the pushed
  image ages out.
- Close: "Clone the repo, swap the host, you're up."

## Asset checklist

- [ ] Run the workflow once against a clean tenant; capture the
      summary screenshot for the article.
- [ ] Capture five Grafana panel screenshots (annotated with
      callouts in Figma / Excalidraw).
- [ ] Record the video against the same fresh state so the demo is
      reproducible.
- [ ] Re-run the workflow weekly via the schedule trigger to keep
      the dashboard "alive" for visitors.

## Why it works as a demo

The workflow exercises six of the eleven differentiator features
in 009-019:

- **009 Online GC** — every push lights up the refcount table; a
  later pull-back exercises the read path without depending on the
  reaper.
- **010 Lazy pull (referrers API)** — the Helm validator and
  attestation upload routes append to `referrers`, visible in the
  detail dashboard.
- **014 Extended scanning** — the deliberately old pip pins surface
  CVE findings; an `org.opencontainers.image.licenses` label on the
  Dockerfile triggers the license detector.
- **017 Cost telemetry** — every push/pull populates
  `usage_events_staging`, drained into the rollups the cost panel
  reads.
- **018 Auto-rebuild** — the `org.opencontainers.image.base.name`
  label fires the lineage detector.
- **019 AI agent** — operators can ask the pilot "show me the
  worst-CVE images today" and get a structured tool call.

Article + video both lean on the dashboard, which means: the more
features that ship, the richer the demo gets without rewriting the
script.

## Dashboards

- [Enterprise Overview](deploy/helm/nebulacr/dashboards/nebulacr-overview.json) — exec view
- [Operations Detail](deploy/helm/nebulacr/dashboards/nebulacr-detail.json) — SRE view

`docs/grafana-dashboards.md` covers installation; this doc covers
the demo flow.
