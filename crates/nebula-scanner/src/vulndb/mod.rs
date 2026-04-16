//! Vulnerability-DB abstraction.
//!
//! Implementations:
//! - `OsvClient` — bootstrap, online, queries api.osv.dev in batches
//! - `NebulaVulnDb` — slice 2, Postgres-backed, fed by NVD/OSV/GHSA ingesters
//!
//! The rest of the scanner holds only `Arc<dyn VulnDb>`.

use async_trait::async_trait;

use crate::model::Vulnerability;
use crate::sbom::Package;
use crate::Result;

pub mod ingest;
pub mod nebula;
pub mod osv;
pub mod severity;

pub use nebula::NebulaVulnDb;
pub use osv::OsvClient;

#[async_trait]
pub trait VulnDb: Send + Sync {
    /// Query the DB for vulnerabilities affecting each package. Returns a
    /// flat list — one `Vulnerability` per (package, advisory) pair, with
    /// `installed_version` filled in from the input.
    async fn query(&self, packages: &[Package]) -> Result<Vec<Vulnerability>>;
}
