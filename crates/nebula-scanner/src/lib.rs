//! NebulaCR image scanner.
//!
//! Pipeline:
//!
//! ```text
//!     manifest.push webhook
//!             │
//!             ▼
//!      queue::Queue  (Tokio in-process; NATS/Kafka impls to come)
//!             │
//!             ▼
//!      image::Puller  (ObjectStore → manifest → layer tarballs)
//!             │
//!             ▼
//!      sbom::extract (dpkg/apk/rpm/npm/cargo/pip/go parsers → CycloneDX)
//!             │
//!             ▼
//!      vulndb::VulnDb  (OsvClient bootstrap; NebulaVulnDb in slice 2)
//!             │
//!             ▼
//!      matcher::evaluate (ecosystem-aware version comparators)
//!             │
//!             ▼
//!      suppress::apply  (Postgres-backed CVE filter)
//!             │
//!             ▼
//!      policy::evaluate → PASS / FAIL + violations
//!             │
//!             ▼
//!      store::Ephemeral (Redis, 1h TTL, keyed by digest)
//!             │
//!             ▼
//!      ai::analyze (Ollama, on-demand via /scan/live/:digest?ai=1)
//! ```

pub mod api;
pub mod config;
pub mod cve_search;
pub mod image;
pub mod matcher;
pub mod model;
pub mod policy;
pub mod queue;
pub mod report;
pub mod runtime;
pub mod sbom;
pub mod settings;
pub mod store;
pub mod suppress;
pub mod vulndb;
pub mod worker;

pub use runtime::ScannerRuntime;

pub use config::ScannerConfig;
pub use model::{PolicyEvaluation, ScanJob, ScanResult, ScanSummary, Severity, Vulnerability};

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("image: {0}")]
    Image(String),
    #[error("sbom: {0}")]
    Sbom(String),
    #[error("vulndb: {0}")]
    VulnDb(String),
    #[error("store: {0}")]
    Store(String),
    #[error("db: {0}")]
    Db(#[from] nebula_db::DbError),
    #[error("ai: {0}")]
    Ai(#[from] nebula_ai::AiError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("object_store: {0}")]
    ObjectStore(#[from] object_store::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ScanError>;
