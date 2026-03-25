use serde::{Deserialize, Serialize};

/// Configuration for the multi-region setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiRegionConfig {
    /// Name of the local region (e.g., "us-east-1").
    pub local_region: String,
    /// All regions in the cluster.
    pub regions: Vec<RegionConfig>,
    /// Replication policy.
    pub replication: ReplicationPolicy,
}

/// Configuration for a single region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionConfig {
    /// Region name (e.g., "us-east-1", "eu-west-1").
    pub name: String,
    /// Registry API endpoint URL for this region.
    pub endpoint: String,
    /// Internal replication endpoint URL (e.g., "http://registry-internal:5002").
    pub internal_endpoint: String,
    /// Whether this region is the primary (accepts writes).
    pub is_primary: bool,
    /// Failover priority (lower = higher priority for promotion).
    pub priority: u32,
}

/// Controls how data is replicated between regions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    /// Replication mode.
    pub mode: ReplicationMode,
    /// Maximum acceptable replication lag in seconds before alerting.
    pub max_lag_secs: u64,
    /// Number of objects to replicate per batch.
    pub batch_size: usize,
    /// Interval in seconds between replication sweeps.
    pub sweep_interval_secs: u64,
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        Self {
            mode: ReplicationMode::Async,
            max_lag_secs: 60,
            batch_size: 50,
            sweep_interval_secs: 10,
        }
    }
}

/// How replication is performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplicationMode {
    /// Eventual consistency: replicate in the background.
    Async,
    /// Wait for at least one secondary to acknowledge before confirming the write.
    SemiSync,
}

impl Default for MultiRegionConfig {
    fn default() -> Self {
        Self {
            local_region: "us-east-1".into(),
            regions: vec![],
            replication: ReplicationPolicy::default(),
        }
    }
}
