use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{AiError, CveAnalyzer, Result};

#[derive(Debug, Clone)]
pub struct OllamaConfig {
    pub endpoint: String,
    pub model: String,
    pub request_timeout: Duration,
    pub num_ctx: u32,
    pub temperature: f32,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:11434".into(),
            model: "qwen2.5-coder:7b".into(),
            // CPU inference is slow; GPU (P4200) handles qwen2.5-coder:7b in ~5-15s
            // for a short JSON answer. Leave headroom.
            // 5 minutes — generous headroom for contended GPUs and queue wait.
            request_timeout: Duration::from_secs(300),
            num_ctx: 8192,
            temperature: 0.2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInput {
    pub cve_id: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: String,
    pub description: Option<String>,
    pub ecosystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveAnalysis {
    pub risk_summary: String,
    pub fix_recommendation: String,
    /// One of: "Immediate", "High", "Medium", "Low", "Informational".
    pub priority: String,
    /// Free-form notes (e.g. "not exploitable without attacker-controlled input").
    pub notes: Option<String>,
}

#[derive(Clone)]
pub struct OllamaClient {
    http: reqwest::Client,
    config: OllamaConfig,
}

impl OllamaClient {
    pub fn new(config: OllamaConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()?;
        Ok(Self { http, config })
    }

    /// Round-trip to Ollama's `/api/tags` as a readiness probe.
    pub async fn ping(&self) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct TagsResp {
            models: Vec<ModelEntry>,
        }
        #[derive(Deserialize)]
        struct ModelEntry {
            name: String,
        }
        let url = format!("{}/api/tags", self.config.endpoint);
        let resp: TagsResp = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(resp.models.into_iter().map(|m| m.name).collect())
    }
}

#[async_trait]
impl CveAnalyzer for OllamaClient {
    async fn analyze(&self, input: &CveInput) -> Result<CveAnalysis> {
        let prompt = build_prompt(input);
        debug!(cve = %input.cve_id, "sending cve analysis prompt to ollama");

        #[derive(Serialize)]
        struct GenReq<'a> {
            model: &'a str,
            prompt: String,
            stream: bool,
            format: &'a str,
            options: GenOptions,
        }
        #[derive(Serialize)]
        struct GenOptions {
            temperature: f32,
            num_ctx: u32,
        }
        #[derive(Deserialize)]
        struct GenResp {
            response: String,
            #[allow(dead_code)]
            done: bool,
        }

        let req = GenReq {
            model: &self.config.model,
            prompt,
            stream: false,
            format: "json",
            options: GenOptions {
                temperature: self.config.temperature,
                num_ctx: self.config.num_ctx,
            },
        };

        let url = format!("{}/api/generate", self.config.endpoint);
        let resp: GenResp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // Ollama in `format: "json"` mode returns the model's raw text in `response`,
        // which should itself be valid JSON matching our schema.
        let parsed: CveAnalysis = serde_json::from_str(&resp.response).map_err(|e| {
            warn!(error = %e, raw = %resp.response, "ollama returned non-conforming json");
            AiError::Invalid(format!("cannot parse ollama response: {e}"))
        })?;
        Ok(parsed)
    }
}

fn build_prompt(input: &CveInput) -> String {
    let description = input
        .description
        .as_deref()
        .unwrap_or("(no description provided)");
    let fixed = input
        .fixed_version
        .as_deref()
        .unwrap_or("(no fix available)");
    format!(
        r#"You are a container-security analyst. Analyse one vulnerability and reply with STRICT JSON.

Respond with a single JSON object matching exactly this schema, no prose:
{{
  "risk_summary": "2-3 sentences on what an attacker can do and under what preconditions",
  "fix_recommendation": "concrete, actionable step (e.g. 'upgrade openssl to 1.1.1k')",
  "priority": "Immediate|High|Medium|Low|Informational",
  "notes": "optional extra context or null"
}}

Vulnerability:
- CVE: {cve}
- Severity: {severity}
- Ecosystem: {ecosystem}
- Package: {pkg}
- Installed version: {installed}
- Fixed version: {fixed}
- Description: {desc}

Guidance:
- "priority" must reflect real-world exploitability of THIS package in a typical container, not just the CVSS score.
- If the fix is "upgrade", name the exact target version when known.
- Do not invent CVEs, versions, or URLs.
"#,
        cve = input.cve_id,
        severity = input.severity,
        ecosystem = input.ecosystem,
        pkg = input.package,
        installed = input.installed_version,
        fixed = fixed,
        desc = description,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_includes_key_fields() {
        let input = CveInput {
            cve_id: "CVE-2023-0286".into(),
            package: "openssl".into(),
            installed_version: "1.1.1".into(),
            fixed_version: Some("1.1.1t".into()),
            severity: "HIGH".into(),
            description: Some("X.400 address type confusion in X.509 GeneralName".into()),
            ecosystem: "deb".into(),
        };
        let p = build_prompt(&input);
        assert!(p.contains("CVE-2023-0286"));
        assert!(p.contains("openssl"));
        assert!(p.contains("1.1.1t"));
        assert!(p.contains("STRICT JSON"));
    }
}
