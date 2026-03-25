# OpsAPI Integration for NebulaCR

This directory contains the OpsAPI-side components for integrating NebulaCR with [OpsAPI](https://github.com/bwalia/opsapi) as a metadata store.

## Architecture

```
NebulaCR Registry ──webhook──> OpsAPI ──PostgreSQL──> Metadata DB
   (image push/delete)         (REST API)             (categories, tags, etc.)
```

NebulaCR sends webhook events on image push/delete. OpsAPI receives these events, upserts repository and image records, and provides a REST API for managing metadata (categories, labels, descriptions).

## Files

### `migrations/container-registry-metadata.lua`

PostgreSQL migration that creates:

| Table | Purpose |
|-------|---------|
| `container_repositories` | Unique repos (tenant/project/repo) with counters |
| `container_images` | Pushed manifests with digest, size, region |
| `container_image_tags` | Image version tags (e.g. `v1.2`, `latest`) |
| `container_categories` | Hierarchical categories for organizing repos |
| `container_repository_categories` | Repo-to-category assignments |
| `container_repository_tags` | Free-form labels/keywords on repos |
| `container_webhook_events` | Audit log of received webhook events |

### `routes/registry-events.lua`

Webhook receiver endpoint:

- `POST /api/v2/registry/events` — Receives NebulaCR webhook payloads
  - HMAC-SHA256 signature verification
  - Idempotent event processing (deduplication by event ID)
  - Auto-creates repositories and images on `manifest.push`
  - Soft-deletes images on `manifest.delete`

### `routes/registry-metadata.lua`

CRUD API for metadata management:

**Repositories:**
- `GET /api/v2/container-repositories` — List (paginated, filterable)
- `GET /api/v2/container-repositories/:id` — Detail with categories/labels
- `PUT /api/v2/container-repositories/:id` — Update description/visibility
- `DELETE /api/v2/container-repositories/:id` — Delete

**Images & Tags:**
- `GET /api/v2/container-repositories/:id/images` — List images with tags
- `GET /api/v2/container-repositories/:id/tags` — List all version tags

**Categories:**
- `GET /api/v2/container-categories` — List all categories
- `POST /api/v2/container-categories` — Create category
- `PUT /api/v2/container-categories/:id` — Update category
- `DELETE /api/v2/container-categories/:id` — Delete category
- `POST /api/v2/container-repositories/:id/categories` — Assign categories
- `DELETE /api/v2/container-repositories/:id/categories` — Remove categories

**Labels:**
- `GET /api/v2/container-repositories/:id/labels` — List labels
- `POST /api/v2/container-repositories/:id/labels` — Add labels
- `DELETE /api/v2/container-repositories/:id/labels` — Remove labels

**Search:**
- `GET /api/v2/container-search?q=&category=&label=&visibility=` — Full-text search

## Setup

### 1. OpsAPI Side

Copy the migration and route files into your OpsAPI deployment:

```bash
cp migrations/container-registry-metadata.lua /path/to/opsapi/migrations/
cp routes/registry-events.lua /path/to/opsapi/routes/
cp routes/registry-metadata.lua /path/to/opsapi/routes/
```

Run the migration and set the webhook secret:

```bash
export NEBULACR_WEBHOOK_SECRET="your-shared-secret"
```

### 2. NebulaCR Side

Configure webhooks in `config.toml` or via environment variables:

```toml
[webhooks]
enabled = true
timeout_ms = 5000
max_retries = 3

[[webhooks.endpoints]]
name = "opsapi"
url = "http://opsapi:8080/api/v2/registry/events"
secret = "your-shared-secret"
events = ["manifest.push", "manifest.delete"]
```

## Webhook Payload Format

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "event": "manifest.push",
  "timestamp": "2026-03-25T12:00:00Z",
  "data": {
    "tenant": "acme",
    "project": "default",
    "repository": "myapp",
    "reference": "v1.2.3",
    "digest": "sha256:abc123...",
    "size": 52428800,
    "source_region": "us-east-1"
  }
}
```

The `X-NebulaCR-Signature` header contains `sha256=<HMAC-SHA256 hex>` computed over the raw JSON body using the shared secret.
