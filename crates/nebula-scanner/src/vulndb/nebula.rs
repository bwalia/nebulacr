//! Our own Postgres-backed VulnDb. Populated by the NVD/OSV/GHSA ingestion
//! jobs in slice 2. Empty shell for now — trait stays identical so callers
//! don't change when we flip `vulndb: nebula` in config.

use async_trait::async_trait;
use sqlx::PgPool;

use super::VulnDb;
use crate::model::Vulnerability;
use crate::sbom::Package;
use crate::{Result, ScanError};

pub struct NebulaVulnDb {
    #[allow(dead_code)]
    pool: PgPool,
}

impl NebulaVulnDb {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl VulnDb for NebulaVulnDb {
    async fn query(&self, _packages: &[Package]) -> Result<Vec<Vulnerability>> {
        // TODO(slice 2): SELECT from vulnerabilities JOIN affected_ranges,
        // apply per-ecosystem version comparators from crate::matcher.
        Err(ScanError::VulnDb("NebulaVulnDb::query not implemented (slice 2)".into()))
    }
}
