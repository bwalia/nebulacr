//! Anthropic Messages API client (tool-use).
//!
//! Reference: <https://docs.anthropic.com/en/api/messages>
//! Reference: <https://docs.anthropic.com/en/docs/build-with-claude/tool-use>

use super::{
    ChatMessage, ChatRole, LlmClient, LlmError, LlmProvider, LlmStep, LlmToolCall, ToolDescriptor,
};
use async_trait::async_trait;
use serde::Deserialize;

pub struct AnthropicClient {
    pub model: String,
    pub api_key: String,
    pub base_url: String,
    client: reqwest::Client,
}

impl AnthropicClient {
    pub fn new(model: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            api_key: api_key.into(),
            base_url: "https://api.anthropic.com".into(),
            client: reqwest::Client::new(),
        }
    }
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = base.into();
        self
    }
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicBlock>,
    #[serde(default)]
    #[allow(dead_code)]
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum AnthropicBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

#[async_trait]
impl LlmClient for AnthropicClient {
    fn provider(&self) -> LlmProvider {
        LlmProvider::Anthropic
    }
    fn model(&self) -> &str {
        &self.model
    }

    async fn step(
        &self,
        system: Option<&str>,
        messages: &[ChatMessage],
        tools: &[ToolDescriptor],
    ) -> Result<LlmStep, LlmError> {
        // Build Anthropic-shaped message array.
        let msgs: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| match m.role {
                ChatRole::User => serde_json::json!({"role": "user", "content": m.content}),
                ChatRole::Assistant => {
                    serde_json::json!({"role": "assistant", "content": m.content})
                }
                // Tool results go in as "user" messages with a
                // tool_result content block; we shape that inline.
                ChatRole::Tool => serde_json::json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m.tool_use_id.clone().unwrap_or_default(),
                        "content": m.content,
                    }],
                }),
                // System messages are split out via the top-level
                // `system` field; passing through as user is a
                // reasonable fallback.
                ChatRole::System => serde_json::json!({"role": "user", "content": m.content}),
            })
            .collect();

        let tools_arr: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": 4096,
            "messages": msgs,
        });
        if let Some(s) = system {
            body["system"] = serde_json::Value::String(s.to_string());
        }
        if !tools_arr.is_empty() {
            body["tools"] = serde_json::Value::Array(tools_arr);
        }

        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(LlmError::Provider {
                status: status.as_u16(),
                body,
            });
        }
        let parsed: AnthropicResponse = resp
            .json()
            .await
            .map_err(|e| LlmError::Parse(e.to_string()))?;

        // Tool-use blocks override text-only output: if any tool_use
        // appears, we return ToolCalls and let the loop dispatch.
        let mut tool_calls = Vec::new();
        let mut text = String::new();
        for block in parsed.content {
            match block {
                AnthropicBlock::Text { text: t } => {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&t);
                }
                AnthropicBlock::ToolUse { id, name, input } => {
                    tool_calls.push(LlmToolCall { id, name, input });
                }
            }
        }
        if !tool_calls.is_empty() {
            Ok(LlmStep::ToolCalls(tool_calls))
        } else {
            Ok(LlmStep::Text(text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_response() {
        let raw = serde_json::json!({
            "content": [
                {"type": "text", "text": "hello"}
            ],
            "stop_reason": "end_turn"
        });
        let parsed: AnthropicResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.content.len(), 1);
    }

    #[test]
    fn parses_tool_use_response() {
        let raw = serde_json::json!({
            "content": [
                {"type": "tool_use", "id": "tu_01", "name": "ping",
                 "input": {"message": "hi"}}
            ],
            "stop_reason": "tool_use"
        });
        let parsed: AnthropicResponse = serde_json::from_value(raw).unwrap();
        match &parsed.content[0] {
            AnthropicBlock::ToolUse { name, .. } => assert_eq!(name, "ping"),
            _ => panic!("expected tool_use"),
        }
    }
}
