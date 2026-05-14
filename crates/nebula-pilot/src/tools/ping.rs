//! Trivial ping tool — used by tests + a smoke-test for tool dispatch.

use crate::tool::{Destructiveness, Tool, ToolCtx, ToolError, ToolOutput, ToolPermission};
use async_trait::async_trait;

pub struct PingTool;

#[async_trait]
impl Tool for PingTool {
    fn name(&self) -> &'static str {
        "ping"
    }

    fn description(&self) -> &'static str {
        "Returns the input message — used to verify tool dispatch."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "message": { "type": "string" }
            },
            "required": ["message"]
        })
    }

    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:read".into())
    }

    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::ReadOnly
    }

    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let msg = input
            .get("message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing 'message'".into()))?;
        Ok(ToolOutput::allow(serde_json::json!({ "echo": msg })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ToolRegistry;

    #[tokio::test]
    async fn ping_round_trip_via_registry() {
        let reg = ToolRegistry::new().register(PingTool);
        let ctx = ToolCtx {
            actor_sub: "u".into(),
            tenant: "acme".into(),
            dry_run: false,
        };
        let out = reg
            .invoke("ping", &ctx, serde_json::json!({ "message": "hi" }))
            .await
            .unwrap();
        assert_eq!(out.data["echo"], "hi");
    }

    #[tokio::test]
    async fn ping_rejects_missing_input() {
        let reg = ToolRegistry::new().register(PingTool);
        let ctx = ToolCtx {
            actor_sub: "u".into(),
            tenant: "acme".into(),
            dry_run: false,
        };
        let err = reg
            .invoke("ping", &ctx, serde_json::json!({}))
            .await
            .unwrap_err();
        matches!(err, ToolError::InvalidInput(_));
    }

    #[tokio::test]
    async fn registry_returns_not_found_for_unknown_tool() {
        let reg = ToolRegistry::new().register(PingTool);
        let ctx = ToolCtx {
            actor_sub: "u".into(),
            tenant: "acme".into(),
            dry_run: false,
        };
        let err = reg
            .invoke("nope", &ctx, serde_json::json!({}))
            .await
            .unwrap_err();
        matches!(err, ToolError::NotFound(_));
    }
}
