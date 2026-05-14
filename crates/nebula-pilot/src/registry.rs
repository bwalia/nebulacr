//! ToolRegistry — name -> Arc<dyn Tool> dispatcher.

use crate::tool::{Tool, ToolCtx, ToolError, ToolOutput};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
pub struct ToolRegistry {
    tools: HashMap<&'static str, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<T: Tool + 'static>(mut self, tool: T) -> Self {
        let name = tool.name();
        self.tools.insert(name, Arc::new(tool));
        self
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.tools.keys().copied().collect()
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(name).cloned()
    }

    pub async fn invoke(
        &self,
        name: &str,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let tool = self
            .get(name)
            .ok_or_else(|| ToolError::NotFound(format!("unknown tool: {name}")))?;
        tool.invoke(ctx, input).await
    }
}
