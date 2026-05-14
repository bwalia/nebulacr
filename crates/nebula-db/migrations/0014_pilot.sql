-- 019 AI agent (nebula-pilot) — sessions, messages, tool invocations.

CREATE TABLE IF NOT EXISTS pilot_sessions (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    actor_sub       TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    title           TEXT
);
CREATE INDEX IF NOT EXISTS pilot_sessions_actor_idx
    ON pilot_sessions (actor_sub, started_at DESC);

CREATE TABLE IF NOT EXISTS pilot_messages (
    id              BIGSERIAL PRIMARY KEY,
    session_id      UUID NOT NULL REFERENCES pilot_sessions(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,                  -- user | assistant | tool
    content         JSONB NOT NULL,
    tokens_in       INT,
    tokens_out      INT,
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS pilot_messages_session_idx
    ON pilot_messages (session_id, at);

CREATE TABLE IF NOT EXISTS pilot_tool_invocations (
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
CREATE INDEX IF NOT EXISTS pilot_tool_invocations_tool_idx
    ON pilot_tool_invocations (tool, at DESC);

CREATE TABLE IF NOT EXISTS pilot_approvals (
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

CREATE TABLE IF NOT EXISTS pilot_token_spend (
    tenant          TEXT NOT NULL,
    bucket_day      DATE NOT NULL,
    provider        TEXT NOT NULL,
    tokens_in       BIGINT NOT NULL DEFAULT 0,
    tokens_out      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant, bucket_day, provider)
);
