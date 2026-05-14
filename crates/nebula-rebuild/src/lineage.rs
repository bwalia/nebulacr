//! Lineage detection from an OCI image config.
//!
//! Two paths, in priority order:
//! 1. `org.opencontainers.image.base.name` annotation in the image
//!    config (set by `docker buildx`, `buildkit`, etc.).
//! 2. `history[].created_by` entries with a leading `FROM <ref>`.
//!
//! Returns the detected base image reference + a confidence band.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LineageConfidence {
    Label,
    History,
    Inferred,
}

impl LineageConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Label => "label",
            Self::History => "history",
            Self::Inferred => "inferred",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageHint {
    pub base_ref: String,
    pub confidence: LineageConfidence,
}

#[derive(Debug, Deserialize)]
struct ImageConfig {
    #[serde(default)]
    config: Option<InnerConfig>,
    #[serde(default)]
    history: Vec<HistoryEntry>,
}

#[derive(Debug, Deserialize)]
struct InnerConfig {
    #[serde(default, rename = "Labels")]
    labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct HistoryEntry {
    #[serde(default)]
    created_by: Option<String>,
}

pub fn detect_lineage(image_config_bytes: &[u8]) -> Option<LineageHint> {
    let cfg: ImageConfig = serde_json::from_slice(image_config_bytes).ok()?;

    // 1) Label-based.
    let label = cfg
        .config
        .as_ref()
        .and_then(|c| c.labels.as_ref())
        .and_then(|labels| labels.get("org.opencontainers.image.base.name"))
        .filter(|s| !s.is_empty());
    if let Some(base) = label {
        return Some(LineageHint {
            base_ref: base.clone(),
            confidence: LineageConfidence::Label,
        });
    }

    // 2) History-based — scan `created_by` entries for a leading `FROM`.
    for h in cfg.history.iter() {
        if let Some(line) = &h.created_by {
            // Common shapes:
            //   "/bin/sh -c #(nop) FROM debian:bookworm-slim"
            //   "FROM python:3.12-slim"
            //   "buildkit.dockerfile.v0 FROM ghcr.io/foo/bar:latest"
            if let Some(idx) = line.find("FROM ") {
                let tail = &line[idx + 5..];
                let base = tail.split_whitespace().next().unwrap_or("");
                if !base.is_empty() {
                    return Some(LineageHint {
                        base_ref: base.to_string(),
                        confidence: LineageConfidence::History,
                    });
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_takes_precedence() {
        let body = serde_json::json!({
            "config": {
                "Labels": {
                    "org.opencontainers.image.base.name": "debian:bookworm-slim"
                }
            },
            "history": [
                { "created_by": "/bin/sh -c #(nop) FROM ubuntu:24.04" }
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let hint = detect_lineage(&bytes).unwrap();
        assert_eq!(hint.base_ref, "debian:bookworm-slim");
        assert_eq!(hint.confidence, LineageConfidence::Label);
    }

    #[test]
    fn history_fallback_finds_first_from() {
        let body = serde_json::json!({
            "history": [
                { "created_by": "/bin/sh -c #(nop) FROM ubuntu:24.04" },
                { "created_by": "RUN apt-get update" }
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let hint = detect_lineage(&bytes).unwrap();
        assert_eq!(hint.base_ref, "ubuntu:24.04");
        assert_eq!(hint.confidence, LineageConfidence::History);
    }

    #[test]
    fn returns_none_when_no_signal() {
        let body = serde_json::json!({
            "history": [
                { "created_by": "RUN apt-get update" }
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        assert!(detect_lineage(&bytes).is_none());
    }

    #[test]
    fn handles_garbage_json() {
        assert!(detect_lineage(b"not json").is_none());
    }
}
