//! Policy engine. Task #10.
//!
//! YAML rules of the form:
//!
//! ```yaml
//! block_if:
//!   critical: ">0"
//!   high: ">5"
//! ```
//!
//! Suppression-aware: suppressed CVEs are excluded from the counts used to
//! evaluate thresholds but remain visible in the scan report.

use serde::{Deserialize, Serialize};

use crate::model::{
    PolicyEvaluation, PolicyStatus, PolicyViolation, ScanSummary, Severity, Vulnerability,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub block_if: BlockRules,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockRules {
    pub critical: Option<String>,
    pub high: Option<String>,
    pub medium: Option<String>,
    pub low: Option<String>,
}

impl Policy {
    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        Ok(serde_yaml::from_str(s)?)
    }

    pub fn evaluate(&self, vulns: &[Vulnerability]) -> PolicyEvaluation {
        let mut summary = ScanSummary::default();
        for v in vulns.iter().filter(|v| !v.suppressed) {
            summary.add(v.severity);
        }

        let mut violations = Vec::new();
        self.check(
            Severity::Critical,
            summary.critical,
            self.block_if.critical.as_deref(),
            &mut violations,
        );
        self.check(
            Severity::High,
            summary.high,
            self.block_if.high.as_deref(),
            &mut violations,
        );
        self.check(
            Severity::Medium,
            summary.medium,
            self.block_if.medium.as_deref(),
            &mut violations,
        );
        self.check(
            Severity::Low,
            summary.low,
            self.block_if.low.as_deref(),
            &mut violations,
        );

        let status = if violations.is_empty() {
            PolicyStatus::Pass
        } else {
            PolicyStatus::Fail
        };
        let reason = if violations.is_empty() {
            None
        } else {
            Some(format!("{} policy violation(s)", violations.len()))
        };
        PolicyEvaluation {
            status,
            violations,
            reason,
        }
    }

    fn check(
        &self,
        severity: Severity,
        count: u32,
        rule: Option<&str>,
        out: &mut Vec<PolicyViolation>,
    ) {
        let Some(rule) = rule else { return };
        if compare(count, rule) {
            out.push(PolicyViolation {
                severity,
                count,
                threshold: rule.to_string(),
            });
        }
    }
}

/// Evaluate `count OP value` for rules like `">5"`, `">=1"`, `"=0"`.
fn compare(count: u32, rule: &str) -> bool {
    let rule = rule.trim();
    let (op, rest) = if let Some(r) = rule.strip_prefix(">=") {
        (">=", r)
    } else if let Some(r) = rule.strip_prefix("<=") {
        ("<=", r)
    } else if let Some(r) = rule.strip_prefix('>') {
        (">", r)
    } else if let Some(r) = rule.strip_prefix('<') {
        ("<", r)
    } else if let Some(r) = rule.strip_prefix('=') {
        ("=", r)
    } else {
        return false;
    };
    let Ok(threshold) = rest.trim().parse::<u32>() else {
        return false;
    };
    match op {
        ">" => count > threshold,
        ">=" => count >= threshold,
        "<" => count < threshold,
        "<=" => count <= threshold,
        "=" => count == threshold,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_on_critical() {
        let p = Policy::from_yaml("block_if:\n  critical: \">0\"\n  high: \">5\"\n").unwrap();
        let vulns = vec![Vulnerability {
            id: "CVE-2024-0001".into(),
            aliases: vec![],
            package: "openssl".into(),
            ecosystem: "deb".into(),
            installed_version: "1.1.1".into(),
            fixed_version: None,
            severity: Severity::Critical,
            cvss_score: None,
            summary: None,
            description: None,
            layer_digest: None,
            references: vec![],
            suppressed: false,
        }];
        let eval = p.evaluate(&vulns);
        assert_eq!(eval.status, PolicyStatus::Fail);
        assert_eq!(eval.violations.len(), 1);
    }

    #[test]
    fn suppressed_not_counted() {
        let p = Policy::from_yaml("block_if:\n  critical: \">0\"\n").unwrap();
        let mut v = Vulnerability {
            id: "CVE-X".into(),
            aliases: vec![],
            package: "p".into(),
            ecosystem: "deb".into(),
            installed_version: "1".into(),
            fixed_version: None,
            severity: Severity::Critical,
            cvss_score: None,
            summary: None,
            description: None,
            layer_digest: None,
            references: vec![],
            suppressed: true,
        };
        v.suppressed = true;
        let eval = p.evaluate(&[v]);
        assert_eq!(eval.status, PolicyStatus::Pass);
    }
}
