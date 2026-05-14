//! `Tool` trait — every registry operation the agent can invoke is a Tool.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destructiveness {
    ReadOnly,
    Mutating,
    Destructive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPermission(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCtx {
    pub actor_sub: String,
    pub tenant: String,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolOutcome {
    Allowed,
    Denied,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    pub outcome: ToolOutcome,
    pub data: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn input_schema(&self) -> serde_json::Value;
    fn permission(&self) -> ToolPermission;
    fn destructiveness(&self) -> Destructiveness;
    fn supports_dry_run(&self) -> bool {
        matches!(
            self.destructiveness(),
            Destructiveness::Mutating | Destructiveness::Destructive
        )
    }

    async fn invoke(
        &self,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError>;
}

/// Marker output helpers.
impl ToolOutput {
    pub fn allow(data: serde_json::Value) -> Self {
        Self {
            outcome: ToolOutcome::Allowed,
            data,
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            outcome: ToolOutcome::Denied,
            data: serde_json::json!({ "reason": reason.into() }),
        }
    }
}
