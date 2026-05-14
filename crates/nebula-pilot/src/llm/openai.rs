//! OpenAI Chat Completions client (function calling shape).
//!
//! Uses the `tools` + `tool_calls` API. Compatible with any
//! OpenAI-compatible server (vLLM, OpenRouter, Azure-OpenAI with the
//! correct base_url) by overriding `base_url`.

use super::{
    ChatMessage, ChatRole, LlmClient, LlmError, LlmProvider, LlmStep, LlmToolCall, ToolDescriptor,
};
use async_trait::async_trait;
use serde::Deserialize;

pub struct OpenAiClient {
    pub model: String,
    pub api_key: String,
    pub base_url: String,
    client: reqwest::Client,
}

impl OpenAiClient {
    pub fn new(model: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            api_key: api_key.into(),
            base_url: "https://api.openai.com".into(),
            client: reqwest::Client::new(),
        }
    }
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = base.into();
        self
    }
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiAssistantMessage,
}

#[derive(Deserialize)]
struct OpenAiAssistantMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<OpenAiToolCall>,
}

#[derive(Deserialize)]
struct OpenAiToolCall {
    id: String,
    function: OpenAiFunctionCall,
}

#[derive(Deserialize)]
struct OpenAiFunctionCall {
    name: String,
    arguments: String, // JSON string
}

#[async_trait]
impl LlmClient for OpenAiClient {
    fn provider(&self) -> LlmProvider {
        LlmProvider::OpenAi
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
        // Build OpenAI-shaped message array.
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
                    "tool_call_id": m.tool_use_id.clone().unwrap_or_default(),
                    "name": m.tool_name.clone().unwrap_or_default(),
                    "content": m.content,
                }),
            });
        }

        // Tools as OpenAI function-call definitions.
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
        });
        if !tools_arr.is_empty() {
            body["tools"] = serde_json::Value::Array(tools_arr);
        }

        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
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
        let parsed: OpenAiResponse = resp
            .json()
            .await
            .map_err(|e| LlmError::Parse(e.to_string()))?;
        let choice = parsed
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| LlmError::Parse("no choices".into()))?;

        if !choice.message.tool_calls.is_empty() {
            let calls: Vec<LlmToolCall> = choice
                .message
                .tool_calls
                .into_iter()
                .map(|c| {
                    let input: serde_json::Value = serde_json::from_str(&c.function.arguments)
                        .unwrap_or(serde_json::Value::Object(Default::default()));
                    LlmToolCall {
                        id: c.id,
                        name: c.function.name,
                        input,
                    }
                })
                .collect();
            Ok(LlmStep::ToolCalls(calls))
        } else {
            Ok(LlmStep::Text(choice.message.content.unwrap_or_default()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_response() {
        let raw = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "hi"}
            }]
        });
        let parsed: OpenAiResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.choices[0].message.content.as_deref(), Some("hi"));
    }

    #[test]
    fn parses_tool_call_response() {
        let raw = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_01",
                        "type": "function",
                        "function": {
                            "name": "ping",
                            "arguments": "{\"message\":\"hi\"}"
                        }
                    }]
                }
            }]
        });
        let parsed: OpenAiResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.choices[0].message.tool_calls.len(), 1);
        assert_eq!(
            parsed.choices[0].message.tool_calls[0].function.name,
            "ping"
        );
    }
}
