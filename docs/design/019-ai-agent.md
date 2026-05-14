# 019 — AI Agent for Registry Automation (`nebula-pilot`)

> **Summary.** A natural-language operator agent for NebulaCR — pick
> a model (Anthropic Claude, OpenAI, or local Ollama), expose a
> structured tool registry over MCP **and** an HTTP chat surface,
> and let the agent invoke registry operations the same way a human
> operator would: trigger scans, suppress CVEs, run GC, promote
> tags, rotate signing keys, draft Dockerfile fixes. Modelled on
> [`bwalia/dockpilot`](https://github.com/bwalia/dockpilot) but with
> structured tool calls (instead of free-text shell), per-tool RBAC,
> dry-run on destructive ops, and full audit-log integration with
> 005.

## a. Problem statement

Registry operators spend most of their time on a small recurring
list: "rescan that image with the latest CVE feed", "suppress this
false-positive CVE for our team", "promote the latest tag of
`acme/api` from staging to prod", "GC is lagging — what's queued?".
Every action requires a different sub-CLI, a different set of
flags, and a different doc page. `bwalia/dockpilot` proved (for the
Docker daemon) that an LLM can compress this UX into a single
chat-style entry point. NebulaCR has the right primitives — every
admin operation is already a CLI subcommand or an HTTP endpoint —
but no integrated agent surface. The dual-use risk (an agent typing
`run_gc` is fine; typing `delete every tag` is not) is what dockpilot
left under-served; we tighten that with structured tools, RBAC, and
mandatory audit.

## b. Proposed approach

New crate `nebula-pilot`. Three pieces:

### 1. Tool registry

Every operator action is a registered `Tool` with a typed input
schema, a permission requirement, a destructiveness flag, and a
handler:

```rust
// crates/nebula-pilot/src/tool.rs
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn input_schema(&self) -> serde_json::Value;     // JSON Schema
    fn requires_permission(&self) -> Permission;
    fn destructiveness(&self) -> Destructiveness;     // ReadOnly | Mutating | Destructive
    fn supports_dry_run(&self) -> bool;

    async fn invoke(&self, ctx: &ToolCtx, input: serde_json::Value)
        -> Result<ToolOutput, ToolError>;
}
```

Initial tool catalogue (one struct per item, dispatched by name):

| Tool                       | Destructiveness | Permission         | Notes                                        |
| -------------------------- | --------------- | ------------------ | -------------------------------------------- |
| `list_repositories`        | ReadOnly        | `tenant:read`      | Returns paged list                           |
| `inspect_image`            | ReadOnly        | `repo:read`        | Tag info, scan summary, signatures           |
| `trigger_scan`             | Mutating        | `repo:scan`        | Invokes existing `POST /v2/scan`             |
| `get_scan_findings`        | ReadOnly        | `repo:read`        | Reads from 014 findings table                |
| `suppress_finding`         | Mutating        | `tenant:write`     | Audited; reuses 014 suppression CRUD          |
| `unsuppress_finding`       | Mutating        | `tenant:write`     | Audited                                       |
| `run_gc_reconcile`         | Mutating        | `tenant:admin`     | Maps to 009 reconciler                       |
| `pause_gc` / `resume_gc`   | Mutating        | `tenant:admin`     |                                              |
| `promote_tag`              | Mutating        | `repo:promote`     | Atomic via 006                                |
| `delete_tag`               | Destructive     | `repo:delete`      | dry-run mandatory in `Mutating` mode         |
| `delete_repository`        | Destructive     | `tenant:admin`     | dry-run + confirm phrase mandatory           |
| `set_ttl`                  | Mutating        | `repo:push`        | 013 TTL header surface                       |
| `rotate_signing_key`       | Destructive     | `tenant:admin`     | 001; gated by approval                        |
| `import_repo`              | Mutating        | `tenant:admin`     | Wraps 012                                    |
| `propose_dockerfile_fix`   | ReadOnly        | `repo:read`        | Reuses existing AI fix endpoint              |
| `query_audit`              | ReadOnly        | `tenant:audit`     | 005                                           |
| `get_cost_report`          | ReadOnly        | `tenant:read`      | 017                                           |
| `trigger_rebuild`          | Mutating        | `tenant:admin`     | 018 manual fire                              |

The catalogue is the contract surface for the agent — adding a new
NebulaCR feature means registering one `Tool` impl and the agent
inherits it.

### 2. Multi-backend LLM client

```rust
// crates/nebula-pilot/src/llm/mod.rs
#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn step(&self, msgs: &[ChatMessage], tools: &[ToolDescriptor])
        -> Result<LlmStep, LlmError>;
}

pub struct AnthropicClient { /* tool-use API */ }
pub struct OpenAiClient { /* function calling */ }
pub struct OllamaClient { /* json mode + manual loop, dockpilot-style */ }
```

`step()` returns either `LlmStep::Text(...)` or
`LlmStep::ToolCall { name, input }`. The runner loops: dispatch
the tool, append the result as an assistant message, call `step()`
again. Recursion bound: max 10 tool calls per user message, max
30s wall clock — protects against runaway loops.

### 3. Surfaces

- **MCP server** (`nebula-mcp` already mentioned in PROMPT.md but
  not yet implemented). Each `Tool` becomes an MCP tool.
  Claude Code, Cursor, Continue, etc. talk to NebulaCR directly.
- **HTTP chat API** (`POST /v2/_pilot/chat`) — JSON `{messages,
  session_id}` in, streamed SSE responses out. Suitable for embedding
  in 007's Web UI as a chat sidebar.
- **CLI** (`nebulacr pilot`) — interactive REPL using the same
  endpoint. `nebulacr pilot "rescan the prod tags pushed in the
  last hour and tell me which still have criticals"`.

Safety rails:

- **Permission check before tool dispatch.** The user's bearer
  token is propagated; agent never bypasses RBAC.
- **Dry-run by default for `Destructive` tools.** Agent must call
  with `confirm: "<typed-phrase>"` for the second pass; the server
  rejects without it. The phrase is generated per-call so a model
  can't reuse one.
- **Approval gate.** `Destructive` ops can be configured to require
  human approval — the agent's response includes a callback URL;
  an admin clicks it to actually execute. Pattern lifted from
  Anthropic's tool-use safety best-practices.
- **Audit every invocation.** Tool name, input, principal, model,
  outcome, dry-run flag — written to 005 in a single transaction.
  Failure to audit fails the tool call.
- **Spend cap.** `nebulacr.toml` carries a per-tenant token budget
  per day (Anthropic / OpenAI tokens). Agent declines further
  steps with a clear message when the cap is hit.
- **No lateral state.** Agent has no shell, no file IO, no
  arbitrary HTTP. It can ONLY invoke the registered tools.

CLI:
- `nebulacr pilot` — interactive REPL.
- `nebulacr pilot --once "..."` — single-shot prompt.
- `nebulacr pilot tools list` — print the tool catalogue.
- `nebulacr pilot sessions list` — saved chat sessions per user.
- `nebulacr mcp serve` — MCP stdio server.

MCP tool surface mirrors the catalogue 1:1.

## c. New/changed CRDs

```yaml
apiVersion: nebulacr.io/v1alpha1
kind: PilotConfig
metadata:
  name: tenant-acme
  namespace: tenant-acme
spec:
  tenantRef: acme
  backend:
    provider: anthropic               # anthropic | openai | ollama
    model: claude-sonnet-4-6
    apiKeyRef:
      name: anthropic-key
      key: api_key
    maxTokensPerDay: 5000000          # daily spend cap
  destructiveOps:
    requireApproval: true             # must click an approval URL
    approvers: ["security-admins"]    # AccessPolicy subjects
  toolAllowList: []                   # empty = all; or whitelist
  toolDenyList: ["delete_repository"] # blocked entirely
  sessionRetentionDays: 30
```

Per-tool deny-list at the tenant level lets a security-conscious
operator say "agent can do everything except delete repositories"
without changing code.

## d. New HTTP routes

| Method | Path                                                       | Auth scope         | Notes                                            |
| ------ | ---------------------------------------------------------- | ------------------ | ------------------------------------------------ |
| POST   | `/v2/_pilot/chat`                                          | `tenant:pilot`     | SSE stream; body `{messages, session_id?}`       |
| GET    | `/v2/_pilot/sessions`                                      | `tenant:pilot`     | List user sessions                               |
| GET    | `/v2/_pilot/sessions/{id}`                                 | `tenant:pilot`     | Replay a session                                 |
| DELETE | `/v2/_pilot/sessions/{id}`                                 | `tenant:pilot`     | Forget a session                                 |
| GET    | `/v2/_pilot/tools`                                         | `tenant:read`      | Tool catalogue + schemas                         |
| POST   | `/v2/_pilot/approvals/{id}`                                | `tenant:admin`     | Approve a queued destructive op                  |
| GET    | `/v2/_pilot/usage`                                         | `tenant:admin`     | Token spend per backend                          |

The MCP server is delivered as a separate binary — `nebula-mcp` —
that talks the standard MCP stdio protocol; it imports the same
`Tool` registry crate.

## e. Storage / Postgres schema

```sql
-- 0019_pilot.sql
CREATE TABLE pilot_sessions (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    actor_sub       TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    title           TEXT
);
CREATE INDEX pilot_sessions_actor_idx ON pilot_sessions (actor_sub, started_at DESC);

CREATE TABLE pilot_messages (
    id              BIGSERIAL PRIMARY KEY,
    session_id      UUID NOT NULL REFERENCES pilot_sessions(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,                  -- user | assistant | tool
    content         JSONB NOT NULL,
    tokens_in       INT,
    tokens_out      INT,
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX pilot_messages_session_idx ON pilot_messages (session_id, at);

CREATE TABLE pilot_tool_invocations (
    id              UUID PRIMARY KEY,
    session_id      UUID NOT NULL REFERENCES pilot_sessions(id) ON DELETE CASCADE,
    tool            TEXT NOT NULL,
    input           JSONB NOT NULL,
    outcome         TEXT NOT NULL,                  -- 'allowed' | 'denied' | 'failed'
    output          JSONB,
    error           TEXT,
    dry_run         BOOLEAN NOT NULL,
    actor_sub       TEXT NOT NULL,
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX pilot_tool_invocations_tool_idx ON pilot_tool_invocations (tool, at DESC);

CREATE TABLE pilot_approvals (
    id              UUID PRIMARY KEY,
    session_id      UUID NOT NULL REFERENCES pilot_sessions(id) ON DELETE CASCADE,
    tool            TEXT NOT NULL,
    input           JSONB NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at     TIMESTAMPTZ,
    approved_by     TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    state           TEXT NOT NULL                   -- pending | approved | rejected | expired
);

CREATE TABLE pilot_token_spend (
    tenant          TEXT NOT NULL,
    bucket_day      DATE NOT NULL,
    provider        TEXT NOT NULL,
    tokens_in       BIGINT NOT NULL DEFAULT 0,
    tokens_out      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant, bucket_day, provider)
);
```

Every tool invocation also writes a corresponding row to the 005
audit log — `pilot_tool_invocations` is the in-app history; the
audit log is the legal record.

## f. Failure modes

- **LLM provider down.** `step()` returns `LlmError::ProviderDown`;
  agent surfaces "I can't reach the model right now, try again or
  switch backend." No tool calls fire.
- **LLM hallucinates a tool name.** Dispatcher returns
  `unknown tool` to the model; the model tries again. Hard cap at
  10 retries → session ends with an error message.
- **LLM tries to bypass RBAC** by inventing a parameter. Inputs
  validated against the JSON Schema before dispatch; out-of-range
  values rejected. Permissions checked against the user's actual
  token, not anything the model says.
- **Token spend cap hit mid-conversation.** Last response is "spend
  cap reached"; future messages until midnight UTC return 429.
- **Approval expires before admin clicks.** `pilot_approvals.state =
  expired`; agent informs the user and offers to re-request.
- **Audit DB down.** Tool call refuses to execute (consistency
  bias) and returns a clear error. Read-only tools optionally
  proceed without audit (`audit_required = false` per tool).
- **Prompt injection in image labels / scan output the agent
  reads.** Tool outputs are wrapped in clearly-delimited
  `<tool_result>...</tool_result>` blocks; system prompt instructs
  the model to treat tool output as untrusted data, never as
  instructions. We document this is a residual risk and recommend
  destructive ops always require human approval as defense in
  depth.

## g. Migration story

`[pilot] enabled = false`. Schema and binaries ship; the chat
endpoints return 404. Operators enable per-tenant by writing a
`PilotConfig` CRD with a backend choice and at minimum an API key.
No retroactive impact on existing deployments.

The MCP server is shipped as a side-binary; non-pilot users never
encounter it.

## h. Test plan

| Layer              | Where                                                  | Notes                                       |
| ------------------ | ------------------------------------------------------ | ------------------------------------------- |
| Tool dispatch      | `crates/nebula-pilot/tests/dispatch.rs`                | Invokes each tool with mocked deps          |
| Permission gate    | `crates/nebula-pilot/tests/rbac.rs`                    | Insufficient scope → 403                     |
| Dry-run on destructive | `crates/nebula-pilot/tests/dry_run.rs`             | First call dry, second confirm-required     |
| Approval flow      | `crates/nebula-pilot/tests/approval.rs`                | Pending → admin approves → tool fires       |
| Spend cap          | `crates/nebula-pilot/tests/spend_cap.rs`               | Mock token usage; cap triggers 429          |
| Anthropic backend  | `crates/nebula-pilot/tests/llm_anthropic.rs`           | Mock client; tool-use round trip            |
| OpenAI backend     | `crates/nebula-pilot/tests/llm_openai.rs`              | Mock client                                  |
| Ollama backend     | `crates/nebula-pilot/tests/llm_ollama.rs`              | Mock; JSON-mode parse                       |
| Prompt injection   | `crates/nebula-pilot/tests/prompt_injection.rs`        | Malicious tool output → no privileged call  |
| MCP transport      | `crates/nebula-pilot/tests/mcp_stdio.rs`               | Round-trip MCP call → tool dispatch         |
| End-to-end CLI     | `tests/e2e/pilot_cli.sh`                               | `nebulacr pilot --once "scan acme/prod/api:latest and tell me criticals"` |

## i. Implementation slice count

5 slices, ~5 weeks (largest after 011's mesh — LLM integration is
deceptively wide):

1. `nebula-pilot` crate scaffold + `Tool` trait + initial 8
   read-only tools (no LLM yet) + JSON Schema generation +
   permission gate.
2. `LlmClient` trait + Anthropic backend + chat loop + session +
   message persistence + spend tracking.
3. Mutating + destructive tools (suppress, promote, GC, TTL,
   delete) with dry-run + approval flow.
4. OpenAI + Ollama backends + tenant `PilotConfig` CRD + token
   budget enforcement + audit-log integration.
5. MCP server binary (`nebula-mcp`) + CLI REPL + dashboard chat
   sidebar (handed to 007) + e2e + docs (recipes per backend).
