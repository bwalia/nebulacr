-- ============================================================================
-- NebulaCR Registry Metadata CRUD API
--
-- REST API for managing container repository metadata, categories, and tags.
-- Used by the NebulaCR dashboard and admin tools.
--
-- Routes:
--   GET    /api/v2/container-repositories          List repositories
--   GET    /api/v2/container-repositories/:id       Get repository details
--   PUT    /api/v2/container-repositories/:id       Update repository metadata
--   DELETE /api/v2/container-repositories/:id       Delete repository
--
--   GET    /api/v2/container-repositories/:id/images    List images
--   GET    /api/v2/container-repositories/:id/tags      List image tags
--
--   GET    /api/v2/container-categories             List categories
--   POST   /api/v2/container-categories             Create category
--   PUT    /api/v2/container-categories/:id          Update category
--   DELETE /api/v2/container-categories/:id          Delete category
--
--   POST   /api/v2/container-repositories/:id/categories   Assign categories
--   DELETE /api/v2/container-repositories/:id/categories   Remove categories
--
--   GET    /api/v2/container-repositories/:id/labels       List labels
--   POST   /api/v2/container-repositories/:id/labels       Add labels
--   DELETE /api/v2/container-repositories/:id/labels       Remove labels
--
--   GET    /api/v2/container-search                 Search repositories
-- ============================================================================

local lapis = require("lapis")
local json  = require("cjson.safe")
local db    = require("lapis.db")

local app = lapis.Application()

-- ── Helpers ───────────────────────────────────────────────────────────

local function paginate(self)
  local page     = tonumber(self.params.page) or 1
  local per_page = tonumber(self.params.per_page) or 25
  if per_page > 100 then per_page = 100 end
  local offset = (page - 1) * per_page
  return per_page, offset, page
end

local function get_namespace_id(self)
  -- From OpsAPI middleware: self.namespace.id
  return self.namespace and self.namespace.id or nil
end

-- ── Repositories ──────────────────────────────────────────────────────

-- GET /api/v2/container-repositories
app:get("/api/v2/container-repositories", function(self)
  local per_page, offset, page = paginate(self)
  local namespace_id = get_namespace_id(self)

  local where_clause = "WHERE deleted_at IS NULL"
  local params = {}

  if namespace_id then
    where_clause = where_clause .. " AND namespace_id = " .. db.escape_literal(namespace_id)
  end

  if self.params.tenant then
    where_clause = where_clause .. " AND tenant = " .. db.escape_literal(self.params.tenant)
  end

  if self.params.visibility then
    where_clause = where_clause .. " AND visibility = " .. db.escape_literal(self.params.visibility)
  end

  local repos = db.select("* FROM container_repositories " .. where_clause ..
    " ORDER BY updated_at DESC LIMIT ? OFFSET ?", per_page, offset)

  local count = db.select("COUNT(*) as total FROM container_repositories " .. where_clause)

  return {
    json = {
      data       = repos,
      page       = page,
      per_page   = per_page,
      total      = count[1].total,
    }
  }
end)

-- GET /api/v2/container-repositories/:id
app:get("/api/v2/container-repositories/:id", function(self)
  local repo = db.select("* FROM container_repositories WHERE id = ? LIMIT 1", self.params.id)

  if not repo or #repo == 0 then
    return { status = 404, json = { error = "Repository not found" } }
  end

  -- Include categories and labels
  local categories = db.select([[
    cc.* FROM container_categories cc
    INNER JOIN container_repository_categories crc ON crc.category_id = cc.id
    WHERE crc.repository_id = ?
    ORDER BY cc.sort_order, cc.name
  ]], self.params.id)

  local labels = db.select("tag FROM container_repository_tags WHERE repository_id = ? ORDER BY tag",
    self.params.id)

  local image_count = db.select("COUNT(*) as total FROM container_images WHERE repository_id = ? AND deleted_at IS NULL",
    self.params.id)

  repo[1].categories  = categories
  repo[1].labels      = labels
  repo[1].image_count = image_count[1].total

  return { json = { data = repo[1] } }
end)

-- PUT /api/v2/container-repositories/:id
app:put("/api/v2/container-repositories/:id", function(self)
  local repo = db.select("* FROM container_repositories WHERE id = ? LIMIT 1", self.params.id)
  if not repo or #repo == 0 then
    return { status = 404, json = { error = "Repository not found" } }
  end

  local updates = {}
  if self.params.description ~= nil then updates.description = self.params.description end
  if self.params.visibility  ~= nil then updates.visibility  = self.params.visibility end
  if self.params.is_archived ~= nil then updates.is_archived = self.params.is_archived end
  updates.updated_at = db.raw("CURRENT_TIMESTAMP")

  db.update("container_repositories", updates, { id = self.params.id })

  local updated = db.select("* FROM container_repositories WHERE id = ? LIMIT 1", self.params.id)
  return { json = { data = updated[1] } }
end)

-- DELETE /api/v2/container-repositories/:id
app:delete("/api/v2/container-repositories/:id", function(self)
  local repo = db.select("* FROM container_repositories WHERE id = ? LIMIT 1", self.params.id)
  if not repo or #repo == 0 then
    return { status = 404, json = { error = "Repository not found" } }
  end

  db.delete("container_repositories", { id = self.params.id })
  return { status = 204 }
end)

-- ── Repository images ─────────────────────────────────────────────────

-- GET /api/v2/container-repositories/:id/images
app:get("/api/v2/container-repositories/:id/images", function(self)
  local per_page, offset, page = paginate(self)

  local images = db.select([[
    ci.*, array_agg(cit.tag) FILTER (WHERE cit.tag IS NOT NULL) as tags
    FROM container_images ci
    LEFT JOIN container_image_tags cit ON cit.image_id = ci.id
    WHERE ci.repository_id = ? AND ci.deleted_at IS NULL
    GROUP BY ci.id
    ORDER BY ci.pushed_at DESC
    LIMIT ? OFFSET ?
  ]], self.params.id, per_page, offset)

  local count = db.select("COUNT(*) as total FROM container_images WHERE repository_id = ? AND deleted_at IS NULL",
    self.params.id)

  return {
    json = {
      data     = images,
      page     = page,
      per_page = per_page,
      total    = count[1].total,
    }
  }
end)

-- GET /api/v2/container-repositories/:id/tags
app:get("/api/v2/container-repositories/:id/tags", function(self)
  local tags = db.select([[
    cit.tag, cit.created_at, ci.digest, ci.size_bytes, ci.pushed_at
    FROM container_image_tags cit
    INNER JOIN container_images ci ON ci.id = cit.image_id
    WHERE ci.repository_id = ? AND ci.deleted_at IS NULL
    ORDER BY cit.updated_at DESC
  ]], self.params.id)

  return { json = { data = tags } }
end)

-- ── Categories ────────────────────────────────────────────────────────

-- GET /api/v2/container-categories
app:get("/api/v2/container-categories", function(self)
  local namespace_id = get_namespace_id(self)
  local where_clause = "1=1"

  if namespace_id then
    where_clause = "namespace_id = " .. db.escape_literal(namespace_id) .. " OR namespace_id IS NULL"
  end

  local categories = db.select("* FROM container_categories WHERE " .. where_clause ..
    " ORDER BY sort_order, name")

  return { json = { data = categories } }
end)

-- POST /api/v2/container-categories
app:post("/api/v2/container-categories", function(self)
  if not self.params.name or self.params.name == "" then
    return { status = 400, json = { error = "name is required" } }
  end

  local slug = self.params.slug or self.params.name:lower():gsub("[^%w]+", "-"):gsub("^-+", ""):gsub("-+$", "")
  local namespace_id = get_namespace_id(self)

  local result = db.insert("container_categories", {
    namespace_id = namespace_id,
    parent_id    = self.params.parent_id,
    name         = self.params.name,
    slug         = slug,
    description  = self.params.description,
    icon         = self.params.icon,
    sort_order   = self.params.sort_order or 0,
  }, { returning = "*" })

  return { status = 201, json = { data = result } }
end)

-- PUT /api/v2/container-categories/:id
app:put("/api/v2/container-categories/:id", function(self)
  local cat = db.select("* FROM container_categories WHERE id = ? LIMIT 1", self.params.id)
  if not cat or #cat == 0 then
    return { status = 404, json = { error = "Category not found" } }
  end

  local updates = {}
  if self.params.name        ~= nil then updates.name        = self.params.name end
  if self.params.slug        ~= nil then updates.slug        = self.params.slug end
  if self.params.description ~= nil then updates.description = self.params.description end
  if self.params.icon        ~= nil then updates.icon        = self.params.icon end
  if self.params.parent_id   ~= nil then updates.parent_id   = self.params.parent_id end
  if self.params.sort_order  ~= nil then updates.sort_order  = self.params.sort_order end
  updates.updated_at = db.raw("CURRENT_TIMESTAMP")

  db.update("container_categories", updates, { id = self.params.id })

  local updated = db.select("* FROM container_categories WHERE id = ? LIMIT 1", self.params.id)
  return { json = { data = updated[1] } }
end)

-- DELETE /api/v2/container-categories/:id
app:delete("/api/v2/container-categories/:id", function(self)
  db.delete("container_categories", { id = self.params.id })
  return { status = 204 }
end)

-- ── Repository <-> Category assignment ────────────────────────────────

-- POST /api/v2/container-repositories/:id/categories
-- Body: { "category_ids": [1, 2, 3] }
app:post("/api/v2/container-repositories/:id/categories", function(self)
  local category_ids = self.params.category_ids
  if not category_ids or #category_ids == 0 then
    return { status = 400, json = { error = "category_ids is required" } }
  end

  for _, cat_id in ipairs(category_ids) do
    -- Use ON CONFLICT DO NOTHING for idempotency
    db.query("INSERT INTO container_repository_categories (repository_id, category_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
      self.params.id, cat_id)
  end

  return { status = 200, json = { status = "ok" } }
end)

-- DELETE /api/v2/container-repositories/:id/categories
-- Body: { "category_ids": [1, 2] }
app:delete("/api/v2/container-repositories/:id/categories", function(self)
  local category_ids = self.params.category_ids
  if not category_ids or #category_ids == 0 then
    return { status = 400, json = { error = "category_ids is required" } }
  end

  for _, cat_id in ipairs(category_ids) do
    db.delete("container_repository_categories", {
      repository_id = self.params.id,
      category_id   = cat_id,
    })
  end

  return { status = 200, json = { status = "ok" } }
end)

-- ── Repository labels (free-form tags) ────────────────────────────────

-- GET /api/v2/container-repositories/:id/labels
app:get("/api/v2/container-repositories/:id/labels", function(self)
  local labels = db.select("* FROM container_repository_tags WHERE repository_id = ? ORDER BY tag",
    self.params.id)
  return { json = { data = labels } }
end)

-- POST /api/v2/container-repositories/:id/labels
-- Body: { "labels": ["production", "stable", "gpu"] }
app:post("/api/v2/container-repositories/:id/labels", function(self)
  local labels = self.params.labels
  if not labels or #labels == 0 then
    return { status = 400, json = { error = "labels is required" } }
  end

  for _, label in ipairs(labels) do
    db.query("INSERT INTO container_repository_tags (repository_id, tag) VALUES (?, ?) ON CONFLICT DO NOTHING",
      self.params.id, label)
  end

  return { status = 200, json = { status = "ok" } }
end)

-- DELETE /api/v2/container-repositories/:id/labels
-- Body: { "labels": ["deprecated"] }
app:delete("/api/v2/container-repositories/:id/labels", function(self)
  local labels = self.params.labels
  if not labels or #labels == 0 then
    return { status = 400, json = { error = "labels is required" } }
  end

  for _, label in ipairs(labels) do
    db.delete("container_repository_tags", {
      repository_id = self.params.id,
      tag           = label,
    })
  end

  return { status = 200, json = { status = "ok" } }
end)

-- ── Search ────────────────────────────────────────────────────────────

-- GET /api/v2/container-search?q=myapp&category=base-images&label=production
app:get("/api/v2/container-search", function(self)
  local per_page, offset, page = paginate(self)

  local conditions = { "cr.is_archived = false" }
  local namespace_id = get_namespace_id(self)

  if namespace_id then
    table.insert(conditions, "cr.namespace_id = " .. db.escape_literal(namespace_id))
  end

  -- Text search on repository name and description
  if self.params.q and self.params.q ~= "" then
    local q = "%" .. self.params.q .. "%"
    table.insert(conditions, "(cr.repository ILIKE " .. db.escape_literal(q) ..
      " OR cr.description ILIKE " .. db.escape_literal(q) ..
      " OR cr.tenant ILIKE " .. db.escape_literal(q) .. ")")
  end

  -- Filter by category slug
  if self.params.category and self.params.category ~= "" then
    table.insert(conditions, "EXISTS (SELECT 1 FROM container_repository_categories crc " ..
      "INNER JOIN container_categories cc ON cc.id = crc.category_id " ..
      "WHERE crc.repository_id = cr.id AND cc.slug = " ..
      db.escape_literal(self.params.category) .. ")")
  end

  -- Filter by label
  if self.params.label and self.params.label ~= "" then
    table.insert(conditions, "EXISTS (SELECT 1 FROM container_repository_tags crt " ..
      "WHERE crt.repository_id = cr.id AND crt.tag = " ..
      db.escape_literal(self.params.label) .. ")")
  end

  -- Filter by visibility
  if self.params.visibility and self.params.visibility ~= "" then
    table.insert(conditions, "cr.visibility = " .. db.escape_literal(self.params.visibility))
  end

  local where = table.concat(conditions, " AND ")

  local repos = db.select("cr.* FROM container_repositories cr WHERE " .. where ..
    " ORDER BY cr.pull_count DESC, cr.updated_at DESC LIMIT ? OFFSET ?",
    per_page, offset)

  local count = db.select("COUNT(*) as total FROM container_repositories cr WHERE " .. where)

  return {
    json = {
      data     = repos,
      page     = page,
      per_page = per_page,
      total    = count[1].total,
    }
  }
end)

return app
