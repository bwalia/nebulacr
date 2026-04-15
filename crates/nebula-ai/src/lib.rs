//! NebulaCR AI analyzer.
//!
//! Thin client over Ollama's HTTP API (`/api/generate`). Used by the scanner
//! to enrich CVE reports with a risk summary, fix recommendation, and priority
//! ranking in plain English. Default model: `qwen2.5-coder:7b` served on
//! `http://127.0.0.1:11434` (same host as the registry process).
//!
//! We deliberately call Ollama directly rather than routing through NebulaCB —
//! that product is a Couchbase XDCR platform whose AI module is for log
//! analysis, not CVE analysis.

mod ollama;

pub use ollama::{CveAnalysis, CveInput, OllamaClient, OllamaConfig};

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid response: {0}")]
    Invalid(String),
    #[error("timeout after {0}s")]
    Timeout(u64),
}

pub type Result<T> = std::result::Result<T, AiError>;

/// CVE-analysis interface — Ollama is one implementation; others (vLLM,
/// Anthropic API, local llama.cpp server) can plug in behind the same trait.
#[async_trait]
pub trait CveAnalyzer: Send + Sync {
    async fn analyze(&self, input: &CveInput) -> Result<CveAnalysis>;
}
