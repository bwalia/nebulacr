-- ============================================================================
-- NebulaCR Webhook Event Receiver
--
-- POST /api/v2/registry/events
--
-- Receives webhook payloads from NebulaCR and upserts image/repository
-- metadata. Verifies HMAC-SHA256 signatures when a shared secret is configured.
-- ============================================================================

local lapis   = require("lapis")
local json    = require("cjson.safe")
local db      = require("lapis.db")
local config  = require("lapis.config").get()
local ngx     = ngx
local hmac    = require("resty.hmac")
local str     = require("resty.string")

local app = lapis.Application()

-- ── Signature verification ────────────────────────────────────────────

local function verify_signature(body, signature_header, secret)
  if not secret or secret == "" then
    return true -- No secret configured, skip verification
  end

  if not signature_header then
    return false
  end

  -- Expected format: "sha256=<hex>"
  local expected_prefix = "sha256="
  if signature_header:sub(1, #expected_prefix) ~= expected_prefix then
    return false
  end

  local received_sig = signature_header:sub(#expected_prefix + 1)
  local hmac_sha256  = hmac:new(secret, hmac.ALGOS.SHA256)
  hmac_sha256:update(body)
  local computed_sig = str.to_hex(hmac_sha256:final())

  return computed_sig == received_sig
end

-- ── Webhook event receiver ────────────────────────────────────────────

app:post("/api/v2/registry/events", function(self)
  local body = ngx.req.get_body_data()
  if not body then
    ngx.req.read_body()
    body = ngx.req.get_body_data()
  end

  if not body then
    return { status = 400, json = { error = "Empty request body" } }
  end

  -- Verify webhook signature
  local webhook_secret = os.getenv("NEBULACR_WEBHOOK_SECRET") or config.nebulacr_webhook_secret
  local signature = ngx.req.get_headers()["X-NebulaCR-Signature"]

  if not verify_signature(body, signature, webhook_secret) then
    return { status = 401, json = { error = "Invalid webhook signature" } }
  end

  -- Parse payload
  local payload, err = json.decode(body)
  if not payload then
    return { status = 400, json = { error = "Invalid JSON: " .. (err or "unknown") } }
  end

  local event_id   = payload.id
  local event_type = payload.event
  local data       = payload.data

  if not event_id or not event_type or not data then
    return { status = 400, json = { error = "Missing required fields: id, event, data" } }
  end

  -- Idempotency: check if event already processed
  local existing = db.select("1 FROM container_webhook_events WHERE event_id = ? LIMIT 1", event_id)
  if existing and #existing > 0 then
    return { status = 200, json = { status = "already_processed", event_id = event_id } }
  end

  -- Log the webhook event
  db.insert("container_webhook_events", {
    event_id   = event_id,
    event_type = event_type,
    payload    = body,
    status     = "processing",
  })

  -- Process event based on type
  local ok, process_err = pcall(function()
    if event_type == "manifest.push" then
      process_manifest_push(data)
    elseif event_type == "manifest.delete" then
      process_manifest_delete(data)
    elseif event_type == "blob.push" then
      -- Blob events are logged but don't create metadata records
      -- (blobs are content-addressed layers, not user-facing)
    end
  end)

  if ok then
    db.update("container_webhook_events",
      { status = "processed" },
      { event_id = event_id }
    )
    return { status = 200, json = { status = "processed", event_id = event_id } }
  else
    db.update("container_webhook_events",
      { status = "failed", error = tostring(process_err) },
      { event_id = event_id }
    )
    return { status = 500, json = { error = "Processing failed", detail = tostring(process_err) } }
  end
end)

-- ── Event processors ──────────────────────────────────────────────────

function process_manifest_push(data)
  -- Upsert repository
  local repo = db.select("* FROM container_repositories WHERE tenant = ? AND project = ? AND repository = ? LIMIT 1",
    data.tenant, data.project, data.repository)

  local repo_id
  if repo and #repo > 0 then
    repo_id = repo[1].id
    db.update("container_repositories", {
      push_count = db.raw("push_count + 1"),
      updated_at = db.raw("CURRENT_TIMESTAMP"),
    }, { id = repo_id })
  else
    local result = db.insert("container_repositories", {
      tenant     = data.tenant,
      project    = data.project,
      repository = data.repository,
      push_count = 1,
    }, { returning = "id" })
    repo_id = result.id
  end

  -- Upsert image by digest
  local image = db.select("* FROM container_images WHERE repository_id = ? AND digest = ? LIMIT 1",
    repo_id, data.digest)

  local image_id
  if image and #image > 0 then
    image_id = image[1].id
    db.update("container_images", {
      size_bytes    = data.size or 0,
      source_region = data.source_region,
      pushed_at     = db.raw("CURRENT_TIMESTAMP"),
      deleted_at    = db.raw("NULL"),
      updated_at    = db.raw("CURRENT_TIMESTAMP"),
    }, { id = image_id })
  else
    local result = db.insert("container_images", {
      repository_id = repo_id,
      digest        = data.digest,
      size_bytes    = data.size or 0,
      source_region = data.source_region,
    }, { returning = "id" })
    image_id = result.id
  end

  -- Upsert tag if reference is not a digest
  local ref = data.reference
  if ref and ref ~= "" and not ref:match("^sha256:") then
    -- Move tag: delete old assignment, create new
    local old_tag = db.select("id FROM container_image_tags WHERE image_id IN (SELECT id FROM container_images WHERE repository_id = ?) AND tag = ? LIMIT 1",
      repo_id, ref)

    if old_tag and #old_tag > 0 then
      db.delete("container_image_tags", { id = old_tag[1].id })
    end

    db.insert("container_image_tags", {
      image_id = image_id,
      tag      = ref,
    })
  end
end

function process_manifest_delete(data)
  local repo = db.select("* FROM container_repositories WHERE tenant = ? AND project = ? AND repository = ? LIMIT 1",
    data.tenant, data.project, data.repository)

  if not repo or #repo == 0 then
    return
  end

  local repo_id = repo[1].id

  -- Soft-delete the image (set deleted_at)
  db.update("container_images", {
    deleted_at = db.raw("CURRENT_TIMESTAMP"),
    updated_at = db.raw("CURRENT_TIMESTAMP"),
  }, {
    repository_id = repo_id,
    digest        = data.digest,
  })
end

return app
