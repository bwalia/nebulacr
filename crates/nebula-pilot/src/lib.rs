//! NebulaCR AI agent — `nebula-pilot`.
//!
//! Slice 1 ships:
//! - The `Tool` trait every registry operation implements.
//! - A `ToolRegistry` that dispatches by name.
//! - Four read-only tools wired up: `list_repositories`,
//!   `inspect_image`, `query_audit`, `list_findings`.
//! - The pilot persistence schema.
//!
//! Slice 2 adds the LLM client trait + Anthropic backend + the chat
//! loop. Mutating + destructive tools come in slice 3.

pub mod chat;
pub mod llm;
pub mod registry;
pub mod tool;
pub mod tools;

pub use chat::{ChatConfig, ChatError, ChatTurn, run_turn};
pub use llm::{
    ChatMessage, ChatRole, LlmClient, LlmError, LlmProvider, LlmStep, LlmToolCall, ToolDescriptor,
    anthropic::AnthropicClient, ollama::OllamaClient, openai::OpenAiClient,
};
pub use registry::ToolRegistry;
pub use tool::{
    Destructiveness, Tool, ToolCtx, ToolError, ToolOutcome, ToolOutput, ToolPermission,
};
