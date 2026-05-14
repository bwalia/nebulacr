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
}
