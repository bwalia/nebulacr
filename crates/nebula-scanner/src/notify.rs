//! Outbound alert notifications.
//!
//! Posts a compact summary to a webhook when a scan's policy verdict flips
//! to FAIL. Supports Slack-incoming-webhook, Teams MessageCard, and a
//! generic JSON shape — pick the format matching the webhook URL.
//!
//! Best-effort: a failing POST is logged at warn! and never fails the
//! scan. Configured via `alerts_webhook_url` + `alerts_format` on
//! `ScannerConfig`.

use reqwest::Client;
use serde_json::{Value, json};
use tracing::warn;

use crate::model::{PolicyStatus, ScanResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertFormat {
    Slack,
    Teams,
    Generic,
}

impl AlertFormat {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "slack" => Self::Slack,
            "teams" => Self::Teams,
            _ => Self::Generic,
        }
    }
}

pub struct Notifier {
    http: Client,
    webhook_url: String,
    format: AlertFormat,
}

impl Notifier {
    pub fn new(webhook_url: String, format: AlertFormat) -> Self {
        Self {
            http: Client::new(),
            webhook_url,
            format,
        }
    }

    /// Emit a notification for the scan result. Returns early without a
    /// request when the verdict is PASS — alerts are for noisy-path events,
    /// not confirmations.
    pub async fn on_scan_complete(&self, result: &ScanResult) {
        let Some(pe) = &result.policy_evaluation else {
            return;
        };
        if pe.status != PolicyStatus::Fail {
            return;
        }
        let payload = match self.format {
            AlertFormat::Slack => slack_payload(result),
            AlertFormat::Teams => teams_payload(result),
            AlertFormat::Generic => generic_payload(result),
        };
        if let Err(e) = self
            .http
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
        {
            warn!(error = %e, "scan alert webhook failed");
        }
    }
}

fn summary_line(r: &ScanResult) -> String {
    format!(
        "Critical:{} High:{} Medium:{} Low:{}",
        r.summary.critical, r.summary.high, r.summary.medium, r.summary.low
    )
}

fn image_ref(r: &ScanResult) -> String {
    format!(
        "{}/{}/{}:{} ({})",
        r.tenant,
        r.project,
        r.repository,
        r.reference,
        short_digest(&r.digest)
    )
}

fn short_digest(d: &str) -> String {
    d.strip_prefix("sha256:")
        .unwrap_or(d)
        .chars()
        .take(12)
        .collect()
}

fn slack_payload(r: &ScanResult) -> Value {
    json!({
        "text": format!("🚨 NebulaCR policy FAIL: {}", image_ref(r)),
        "blocks": [
            {"type":"header","text":{"type":"plain_text","text":"NebulaCR scan FAIL"}},
            {"type":"section","fields":[
                {"type":"mrkdwn","text": format!("*Image*\n`{}`", image_ref(r))},
                {"type":"mrkdwn","text": format!("*Summary*\n{}", summary_line(r))},
            ]},
        ],
    })
}

fn teams_payload(r: &ScanResult) -> Value {
    json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "B8262B",
        "summary": "NebulaCR scan FAIL",
        "sections": [{
            "activityTitle": "NebulaCR scan FAIL",
            "facts": [
                {"name":"Image", "value": image_ref(r)},
                {"name":"Summary", "value": summary_line(r)},
            ]
        }]
    })
}

fn generic_payload(r: &ScanResult) -> Value {
    json!({
        "event": "scan.failed",
        "scan_id": r.id,
        "image": image_ref(r),
        "digest": r.digest,
        "tenant": r.tenant,
        "project": r.project,
        "repository": r.repository,
        "reference": r.reference,
        "summary": {
            "critical": r.summary.critical,
            "high": r.summary.high,
            "medium": r.summary.medium,
            "low": r.summary.low,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn fail_result() -> ScanResult {
        ScanResult {
            id: Uuid::nil(),
            digest: "sha256:abcdef123456".into(),
            tenant: "acme".into(),
            project: "web".into(),
            repository: "api".into(),
            reference: "1.0".into(),
            status: ScanStatus::Completed,
            error: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            summary: ScanSummary {
                critical: 2,
                high: 5,
                medium: 0,
                low: 0,
                unknown: 0,
            },
            vulnerabilities: vec![],
            policy_evaluation: Some(PolicyEvaluation {
                status: PolicyStatus::Fail,
                violations: vec![],
                reason: None,
            }),
            packages: vec![],
        }
    }

    #[test]
    fn slack_payload_includes_image_and_summary() {
        let v = slack_payload(&fail_result());
        let rendered = serde_json::to_string(&v).unwrap();
        assert!(rendered.contains("acme/web/api:1.0"));
        assert!(rendered.contains("Critical:2"));
    }

    #[test]
    fn teams_payload_has_fact_rows() {
        let v = teams_payload(&fail_result());
        let rendered = serde_json::to_string(&v).unwrap();
        assert!(rendered.contains("MessageCard"));
        assert!(rendered.contains("acme/web/api:1.0"));
    }

    #[test]
    fn generic_payload_is_flat_json() {
        let v = generic_payload(&fail_result());
        assert_eq!(v["event"], "scan.failed");
        assert_eq!(v["summary"]["high"], 5);
    }

    #[test]
    fn alert_format_parse() {
        assert_eq!(AlertFormat::parse("slack"), AlertFormat::Slack);
        assert_eq!(AlertFormat::parse("TEAMS"), AlertFormat::Teams);
        assert_eq!(AlertFormat::parse("webhook"), AlertFormat::Generic);
    }
}
