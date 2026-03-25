-- ============================================================================
-- NebulaCR Container Registry Metadata Schema
--
-- Migration for OpsAPI to store metadata, categories, and tags for
-- container images managed by NebulaCR. Receives data via webhook
-- notifications from the registry.
--
-- Prerequisites: namespace-system.lua (for namespace_id foreign key)
-- ============================================================================

local schema = require("lapis.db.schema")
local types  = schema.types
local db     = require("lapis.db")

return {
  -- Forward migration
  [1] = function()
    -- ── Container repositories ────────────────────────────────────────
    -- Tracks each unique repository (tenant/project/repo) in the registry.
    schema.create_table("container_repositories", {
      { "id",           types.serial({ primary_key = true }) },
      { "namespace_id", types.integer({ null = true }) },
      { "tenant",       types.varchar({ length = 255 }) },
      { "project",      types.varchar({ length = 255 }) },
      { "repository",   types.varchar({ length = 255 }) },
      { "description",  types.text({ null = true }) },
      { "visibility",   types.varchar({ length = 20, default = "'private'" }) },
      { "is_archived",  types.boolean({ default = false }) },
      { "star_count",   types.integer({ default = 0 }) },
      { "pull_count",   types.integer({ default = 0 }) },
      { "push_count",   types.integer({ default = 0 }) },
      { "created_at",   types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
      { "updated_at",   types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
    })

    db.query("CREATE UNIQUE INDEX idx_container_repos_unique ON container_repositories (tenant, project, repository)")
    db.query("CREATE INDEX idx_container_repos_namespace ON container_repositories (namespace_id)")
    db.query("CREATE INDEX idx_container_repos_visibility ON container_repositories (visibility)")

    -- ── Container images (manifests) ──────────────────────────────────
    -- Each pushed manifest becomes an image record. Tags are tracked separately.
    schema.create_table("container_images", {
      { "id",             types.serial({ primary_key = true }) },
      { "repository_id",  types.integer },
      { "digest",         types.varchar({ length = 128 }) },
      { "size_bytes",     types.bigint({ default = 0 }) },
      { "media_type",     types.varchar({ length = 255, null = true }) },
      { "architecture",   types.varchar({ length = 50, null = true }) },
      { "os",             types.varchar({ length = 50, null = true }) },
      { "source_region",  types.varchar({ length = 100, null = true }) },
      { "pushed_by",      types.varchar({ length = 255, null = true }) },
      { "pushed_at",      types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
      { "deleted_at",     types.time({ null = true }) },
      { "created_at",     types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
      { "updated_at",     types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
    })

    db.query("CREATE UNIQUE INDEX idx_container_images_digest ON container_images (repository_id, digest)")
    db.query("CREATE INDEX idx_container_images_repo ON container_images (repository_id)")
    db.query("CREATE INDEX idx_container_images_pushed ON container_images (pushed_at)")

    -- ── Image tags ────────────────────────────────────────────────────
    -- Maps tag names to image digests. A tag can only point to one image
    -- at a time, but an image can have multiple tags.
    schema.create_table("container_image_tags", {
      { "id",          types.serial({ primary_key = true }) },
      { "image_id",    types.integer },
      { "tag",         types.varchar({ length = 255 }) },
      { "created_at",  types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
      { "updated_at",  types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
    })

    db.query("CREATE UNIQUE INDEX idx_container_tags_unique ON container_image_tags (image_id, tag)")
    db.query("CREATE INDEX idx_container_tags_image ON container_image_tags (image_id)")

    -- ── Categories ────────────────────────────────────────────────────
    -- Hierarchical categories for organizing repositories.
    schema.create_table("container_categories", {
      { "id",           types.serial({ primary_key = true }) },
      { "namespace_id", types.integer({ null = true }) },
      { "parent_id",    types.integer({ null = true }) },
      { "name",         types.varchar({ length = 255 }) },
      { "slug",         types.varchar({ length = 255 }) },
      { "description",  types.text({ null = true }) },
      { "icon",         types.varchar({ length = 100, null = true }) },
      { "sort_order",   types.integer({ default = 0 }) },
      { "created_at",   types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
      { "updated_at",   types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
    })

    db.query("CREATE UNIQUE INDEX idx_container_categories_slug ON container_categories (namespace_id, slug)")
    db.query("CREATE INDEX idx_container_categories_parent ON container_categories (parent_id)")

    -- ── Repository <-> Category junction ──────────────────────────────
    schema.create_table("container_repository_categories", {
      { "id",            types.serial({ primary_key = true }) },
      { "repository_id", types.integer },
      { "category_id",   types.integer },
      { "created_at",    types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
    })

    db.query("CREATE UNIQUE INDEX idx_container_repo_cat_unique ON container_repository_categories (repository_id, category_id)")

    -- ── Repository tags (labels/keywords) ─────────────────────────────
    -- Free-form tags/labels for repository discovery and filtering.
    -- Distinct from image tags (which are version references like "v1.2").
    schema.create_table("container_repository_tags", {
      { "id",            types.serial({ primary_key = true }) },
      { "repository_id", types.integer },
      { "tag",           types.varchar({ length = 100 }) },
      { "created_at",    types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
    })

    db.query("CREATE UNIQUE INDEX idx_container_repo_tags_unique ON container_repository_tags (repository_id, tag)")
    db.query("CREATE INDEX idx_container_repo_tags_tag ON container_repository_tags (tag)")

    -- ── Webhook event log ─────────────────────────────────────────────
    -- Audit trail of all webhook events received from NebulaCR.
    schema.create_table("container_webhook_events", {
      { "id",          types.serial({ primary_key = true }) },
      { "event_id",    types.varchar({ length = 64 }) },
      { "event_type",  types.varchar({ length = 50 }) },
      { "payload",     types.text },
      { "status",      types.varchar({ length = 20, default = "'received'" }) },
      { "error",       types.text({ null = true }) },
      { "received_at", types.time({ default = db.raw("CURRENT_TIMESTAMP") }) },
    })

    db.query("CREATE UNIQUE INDEX idx_webhook_events_id ON container_webhook_events (event_id)")
    db.query("CREATE INDEX idx_webhook_events_type ON container_webhook_events (event_type)")

    -- ── Foreign key constraints ───────────────────────────────────────
    db.query("ALTER TABLE container_images ADD CONSTRAINT fk_images_repo FOREIGN KEY (repository_id) REFERENCES container_repositories(id) ON DELETE CASCADE")
    db.query("ALTER TABLE container_image_tags ADD CONSTRAINT fk_image_tags_image FOREIGN KEY (image_id) REFERENCES container_images(id) ON DELETE CASCADE")
    db.query("ALTER TABLE container_categories ADD CONSTRAINT fk_categories_parent FOREIGN KEY (parent_id) REFERENCES container_categories(id) ON DELETE SET NULL")
    db.query("ALTER TABLE container_repository_categories ADD CONSTRAINT fk_repo_cat_repo FOREIGN KEY (repository_id) REFERENCES container_repositories(id) ON DELETE CASCADE")
    db.query("ALTER TABLE container_repository_categories ADD CONSTRAINT fk_repo_cat_cat FOREIGN KEY (category_id) REFERENCES container_categories(id) ON DELETE CASCADE")
    db.query("ALTER TABLE container_repository_tags ADD CONSTRAINT fk_repo_tags_repo FOREIGN KEY (repository_id) REFERENCES container_repositories(id) ON DELETE CASCADE")
  end,
}
