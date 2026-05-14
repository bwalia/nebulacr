//! Rebuild event emitters.
//!
//! Slice 2 ships:
//! - [`RebuildEmitter`] trait — the boundary every CI integration
//!   implements (GitHub Dispatch / GitLab Triggers / Tekton /
//!   generic webhook).
//! - [`GitHubDispatchEmitter`] — concrete impl that POSTs a
//!   `repository_dispatch` to GitHub's API.
//! - [`RebuildEvent`] — the payload + JSON serialisation shared by
//!   every emitter.
//!
//! GitLab / Tekton / generic webhook emitters land in slice 3.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriggerCause {
    BasePushed,
    CveFixed,
    ScheduledNightly,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildEvent {
    pub trigger: TriggerCause,
    pub fixed_cves: Vec<String>,
    pub upstream_ref: String,
    pub downstream_ref: String,
    pub severity_max: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("rejected by remote: {status} {body}")]
    Rejected { status: u16, body: String },
    #[error("config: {0}")]
    Config(String),
}

#[async_trait]
pub trait RebuildEmitter: Send + Sync {
    fn id(&self) -> &'static str;
    async fn emit(&self, event: &RebuildEvent) -> Result<String, EmitError>;
}

/// Posts a `repository_dispatch` to a GitHub repository, optionally
/// targeting a specific workflow file via `event_type`.
///
/// Reference: <https://docs.github.com/rest/repos/repos#create-a-repository-dispatch-event>
pub struct GitHubDispatchEmitter {
    pub repo: String, // "owner/repo"
    pub token: String,
    pub event_type: String, // e.g. "rebuild-on-cve" — workflow filters on this
    pub api_base: String,   // "https://api.github.com" by default
    client: reqwest::Client,
}

impl GitHubDispatchEmitter {
    pub fn new(
        repo: impl Into<String>,
        token: impl Into<String>,
        event_type: impl Into<String>,
    ) -> Self {
        Self {
            repo: repo.into(),
            token: token.into(),
            event_type: event_type.into(),
            api_base: "https://api.github.com".into(),
            client: reqwest::Client::new(),
        }
    }

    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }
}

#[async_trait]
impl RebuildEmitter for GitHubDispatchEmitter {
    fn id(&self) -> &'static str {
        "github-dispatch"
    }

    async fn emit(&self, event: &RebuildEvent) -> Result<String, EmitError> {
        if !self.repo.contains('/') {
            return Err(EmitError::Config(format!(
                "GitHub repo must be 'owner/name', got {}",
                self.repo
            )));
        }
        let url = format!(
            "{}/repos/{}/dispatches",
            self.api_base.trim_end_matches('/'),
            self.repo
        );
        let body = serde_json::json!({
            "event_type": self.event_type,
            "client_payload": {
                "trigger": match event.trigger {
                    TriggerCause::BasePushed => "base_pushed",
                    TriggerCause::CveFixed => "cve_fixed",
                    TriggerCause::ScheduledNightly => "scheduled_nightly",
                    TriggerCause::Manual => "manual",
                },
                "upstream_ref":   event.upstream_ref,
                "downstream_ref": event.downstream_ref,
                "fixed_cves":     event.fixed_cves,
                "severity_max":   event.severity_max,
            },
        });
        let resp = self
            .client
            .post(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, "nebulacr-rebuild")
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(EmitError::Rejected {
                status: status.as_u16(),
                body,
            });
        }
        Ok(format!("{}", status.as_u16()))
    }
}

// ── GitLab pipeline trigger ──────────────────────────────────────────────────

pub struct GitLabPipelineEmitter {
    pub api_base: String,
    pub project_id: String,
    pub trigger_token: String,
    pub ref_: String,
    client: reqwest::Client,
}

impl GitLabPipelineEmitter {
    pub fn new(
        project_id: impl Into<String>,
        trigger_token: impl Into<String>,
        ref_: impl Into<String>,
    ) -> Self {
        Self {
            api_base: "https://gitlab.com".into(),
            project_id: project_id.into(),
            trigger_token: trigger_token.into(),
            ref_: ref_.into(),
            client: reqwest::Client::new(),
        }
    }
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }
}

#[async_trait]
impl RebuildEmitter for GitLabPipelineEmitter {
    fn id(&self) -> &'static str {
        "gitlab-pipeline"
    }

    async fn emit(&self, event: &RebuildEvent) -> Result<String, EmitError> {
        if self.project_id.is_empty() {
            return Err(EmitError::Config("GitLab project_id is empty".into()));
        }
        let url = format!(
            "{}/api/v4/projects/{}/trigger/pipeline",
            self.api_base.trim_end_matches('/'),
            self.project_id
        );
        let trigger_str = match event.trigger {
            TriggerCause::BasePushed => "base_pushed",
            TriggerCause::CveFixed => "cve_fixed",
            TriggerCause::ScheduledNightly => "scheduled_nightly",
            TriggerCause::Manual => "manual",
        };
        let params = [
            ("token", self.trigger_token.as_str()),
            ("ref", self.ref_.as_str()),
            ("variables[NEBULACR_TRIGGER]", trigger_str),
            ("variables[NEBULACR_UPSTREAM]", event.upstream_ref.as_str()),
            (
                "variables[NEBULACR_DOWNSTREAM]",
                event.downstream_ref.as_str(),
            ),
            (
                "variables[NEBULACR_SEVERITY_MAX]",
                event.severity_max.as_str(),
            ),
        ];
        let resp = self.client.post(&url).form(&params).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(EmitError::Rejected {
                status: status.as_u16(),
                body,
            });
        }
        Ok(format!("{}", status.as_u16()))
    }
}

// ── Generic HMAC webhook ─────────────────────────────────────────────────────

pub struct GenericWebhookEmitter {
    pub url: String,
    pub hmac_secret: String,
    pub header_name: String,
    client: reqwest::Client,
}

impl GenericWebhookEmitter {
    pub fn new(url: impl Into<String>, hmac_secret: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            hmac_secret: hmac_secret.into(),
            header_name: "X-NebulaCR-Signature".into(),
            client: reqwest::Client::new(),
        }
    }
    pub fn with_header_name(mut self, name: impl Into<String>) -> Self {
        self.header_name = name.into();
        self
    }
}

/// Compute the same HMAC the emitter sends. Receivers can call this
/// against the request body + their stored secret and `secure_eq`
/// against the header value to verify the request originated here.
pub fn compute_webhook_signature(secret: &str, body: &[u8]) -> Result<String, EmitError> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| EmitError::Config(format!("hmac key: {e}")))?;
    mac.update(body);
    Ok(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

#[async_trait]
impl RebuildEmitter for GenericWebhookEmitter {
    fn id(&self) -> &'static str {
        "webhook"
    }

    async fn emit(&self, event: &RebuildEvent) -> Result<String, EmitError> {
        if self.hmac_secret.is_empty() {
            return Err(EmitError::Config("hmac_secret is empty".into()));
        }
        let body = serde_json::to_vec(event)
            .map_err(|e| EmitError::Config(format!("event serialise: {e}")))?;
        let sig = compute_webhook_signature(&self.hmac_secret, &body)?;
        let resp = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(&self.header_name, sig)
            .header(reqwest::header::USER_AGENT, "nebulacr-rebuild")
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let resp_body = resp.text().await.unwrap_or_default();
            return Err(EmitError::Rejected {
                status: status.as_u16(),
                body: resp_body,
            });
        }
        Ok(format!("{}", status.as_u16()))
    }
}

// ── Tekton EventListener emitter ─────────────────────────────────────────────

pub struct TektonEventListenerEmitter {
    pub url: String,
    pub auth_header: Option<(String, String)>,
    client: reqwest::Client,
}

impl TektonEventListenerEmitter {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            auth_header: None,
            client: reqwest::Client::new(),
        }
    }
    pub fn with_auth(mut self, header_name: impl Into<String>, value: impl Into<String>) -> Self {
        self.auth_header = Some((header_name.into(), value.into()));
        self
    }
}

#[async_trait]
impl RebuildEmitter for TektonEventListenerEmitter {
    fn id(&self) -> &'static str {
        "tekton-eventlistener"
    }

    async fn emit(&self, event: &RebuildEvent) -> Result<String, EmitError> {
        let mut req = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::USER_AGENT, "nebulacr-rebuild")
            .json(event);
        if let Some((name, value)) = &self.auth_header {
            req = req.header(name, value);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(EmitError::Rejected {
                status: status.as_u16(),
                body,
            });
        }
        Ok(format!("{}", status.as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_malformed_repo() {
        let e = GitHubDispatchEmitter::new("invalid-no-slash", "tok", "rebuild-on-cve");
        let err = e
            .emit(&RebuildEvent {
                trigger: TriggerCause::CveFixed,
                fixed_cves: vec!["CVE-2025-0001".into()],
                upstream_ref: "debian:bookworm-slim".into(),
                downstream_ref: "acme/prod/api:latest".into(),
                severity_max: "high".into(),
            })
            .await
            .unwrap_err();
        match err {
            EmitError::Config(_) => {}
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn event_serialises_lower_snake_trigger() {
        let v = serde_json::to_value(TriggerCause::CveFixed).unwrap();
        assert_eq!(v, serde_json::Value::String("cve_fixed".into()));
    }

    #[tokio::test]
    async fn gitlab_rejects_empty_project_id() {
        let e = GitLabPipelineEmitter::new("", "tok", "main");
        let err = e
            .emit(&RebuildEvent {
                trigger: TriggerCause::Manual,
                fixed_cves: vec![],
                upstream_ref: "x".into(),
                downstream_ref: "y".into(),
                severity_max: "low".into(),
            })
            .await
            .unwrap_err();
        matches!(err, EmitError::Config(_));
    }

    #[tokio::test]
    async fn webhook_rejects_empty_secret() {
        let e = GenericWebhookEmitter::new("https://example.invalid", "");
        let err = e
            .emit(&RebuildEvent {
                trigger: TriggerCause::Manual,
                fixed_cves: vec![],
                upstream_ref: "x".into(),
                downstream_ref: "y".into(),
                severity_max: "low".into(),
            })
            .await
            .unwrap_err();
        matches!(err, EmitError::Config(_));
    }

    #[test]
    fn webhook_signature_is_deterministic() {
        let body = br#"{"ok":true}"#;
        let a = compute_webhook_signature("secret", body).unwrap();
        let b = compute_webhook_signature("secret", body).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("sha256="));
        assert_eq!(a.len(), "sha256=".len() + 64);
    }

    #[test]
    fn webhook_signature_changes_with_secret() {
        let body = b"abc";
        let a = compute_webhook_signature("alpha", body).unwrap();
        let b = compute_webhook_signature("beta", body).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn emitter_ids_are_distinct() {
        let gh = GitHubDispatchEmitter::new("o/r", "t", "evt").id();
        let gl = GitLabPipelineEmitter::new("123", "t", "main").id();
        let wh = GenericWebhookEmitter::new("url", "secret").id();
        let tk = TektonEventListenerEmitter::new("url").id();
        assert_eq!(gh, "github-dispatch");
        assert_eq!(gl, "gitlab-pipeline");
        assert_eq!(wh, "webhook");
        assert_eq!(tk, "tekton-eventlistener");
    }
}
