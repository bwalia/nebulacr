//! Ollama chat client (`/api/chat`).
//!
//! Recent Ollama versions support function/tool calling — the
//! `tools` array uses the OpenAI function-call shape. Older models
//! that don't speak tool-use cleanly fall back to text-only.

use super::{
    ChatMessage, ChatRole, LlmClient, LlmError, LlmProvider, LlmStep, LlmToolCall, ToolDescriptor,
};
use async_trait::async_trait;
use serde::Deserialize;

pub struct OllamaClient {
    pub model: String,
    pub base_url: String,
    client: reqwest::Client,
}

impl OllamaClient {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            base_url: "http://127.0.0.1:11434".into(),
            client: reqwest::Client::new(),
        }
    }
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = base.into();
        self
    }
}

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
}

#[derive(Deserialize)]
struct OllamaMessage {
    #[serde(default)]
    content: String,
    #[serde(default)]
    tool_calls: Vec<OllamaToolCall>,
}

#[derive(Deserialize)]
struct OllamaToolCall {
    function: OllamaFunctionCall,
}

#[derive(Deserialize)]
struct OllamaFunctionCall {
    name: String,
    arguments: serde_json::Value, // Ollama returns the object directly
}

#[async_trait]
impl LlmClient for OllamaClient {
    fn provider(&self) -> LlmProvider {
        LlmProvider::Ollama
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
        let mut msgs: Vec<serde_json::Value> = Vec::new();
        if let Some(s) = system {
            msgs.push(serde_json::json!({"role": "system", "content": s}));
        }
        for m in messages {
            msgs.push(match m.role {
                ChatRole::System => serde_json::json!({"role": "system", "content": m.content}),
                ChatRole::User => serde_json::json!({"role": "user", "content": m.content}),
                ChatRole::Assistant => {
                    serde_json::json!({"role": "assistant", "content": m.content})
                }
                ChatRole::Tool => serde_json::json!({
                    "role": "tool",
                    "content": m.content,
                }),
            });
        }

        let tools_arr: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    },
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": msgs,
            "stream": false,
        });
        if !tools_arr.is_empty() {
            body["tools"] = serde_json::Value::Array(tools_arr);
        }

        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
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
        let parsed: OllamaResponse = resp
            .json()
            .await
            .map_err(|e| LlmError::Parse(e.to_string()))?;

        if !parsed.message.tool_calls.is_empty() {
            let calls: Vec<LlmToolCall> = parsed
                .message
                .tool_calls
                .into_iter()
                .enumerate()
                .map(|(i, c)| LlmToolCall {
                    id: format!("ollama-{i}"),
                    name: c.function.name,
                    input: c.function.arguments,
                })
                .collect();
            Ok(LlmStep::ToolCalls(calls))
        } else {
            Ok(LlmStep::Text(parsed.message.content))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_response() {
        let raw = serde_json::json!({
            "message": {"role": "assistant", "content": "hello"}
        });
        let parsed: OllamaResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.message.content, "hello");
    }

    #[test]
    fn parses_tool_call_response() {
        let raw = serde_json::json!({
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "ping",
                        "arguments": {"message": "hi"}
                    }
                }]
            }
        });
        let parsed: OllamaResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.message.tool_calls[0].function.name, "ping");
    }
}
