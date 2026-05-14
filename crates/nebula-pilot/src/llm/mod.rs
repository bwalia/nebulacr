//! LLM client trait + per-backend impls.
//!
//! The chat loop in `crate::chat` uses these to drive a conversation
//! with structured tool calls. Each impl converts the registry's
//! generic `ToolDescriptor`/`ChatMessage` shapes into provider-
//! specific request payloads and back.
//!
//! Slice scope: trait + Anthropic + OpenAI + Ollama. Real prompt-
//! caching, system-prompt management, and image input are slice 3.

pub mod anthropic;
pub mod ollama;
pub mod openai;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    Anthropic,
    OpenAi,
    Ollama,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    /// When `role == Tool`, names the tool whose result this is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Tool-call id when echoing a tool result back to the model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlmStep {
    /// Plain text response; no tool calls. Conversation may continue.
    Text(String),
    /// Model wants to call one or more tools. Caller dispatches each
    /// and returns the results to the model in the next round.
    ToolCalls(Vec<LlmToolCall>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmToolCall {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("provider error: {status} {body}")]
    Provider { status: u16, body: String },
    #[error("parse: {0}")]
    Parse(String),
    #[error("config: {0}")]
    Config(String),
    #[error("budget exhausted: {0}")]
    Budget(String),
}

#[async_trait]
pub trait LlmClient: Send + Sync {
    fn provider(&self) -> LlmProvider;
    fn model(&self) -> &str;

    /// Single round-trip with the model. Implementations are
    /// responsible for adapting `tools` + `messages` into the
    /// provider's tool-use API.
    async fn step(
        &self,
        system: Option<&str>,
        messages: &[ChatMessage],
        tools: &[ToolDescriptor],
    ) -> Result<LlmStep, LlmError>;
}
