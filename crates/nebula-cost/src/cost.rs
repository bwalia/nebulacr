//! Cost projection helpers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Dollars(pub f64);

impl std::ops::Add for Dollars {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Dollars(self.0 + rhs.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostModel {
    pub egress_per_gb: f64,
    pub storage_per_gb_month: f64,
    /// 1.0 means a cache hit costs the same as origin egress (e.g.
    /// peer cache served from another paid pod). 0.0 = free (in-cluster
    /// peer hit on same VPC).
    #[serde(default = "default_cache_factor")]
    pub cache_egress_factor: f64,
}

fn default_cache_factor() -> f64 {
    1.0
}

impl CostModel {
    /// Project cost for a single hour-bucket aggregation.
    pub fn project_egress(&self, bytes: i64, from_cache: bool) -> Dollars {
        let gb = bytes as f64 / 1_000_000_000.0;
        let factor = if from_cache {
            self.cache_egress_factor
        } else {
            1.0
        };
        Dollars(gb * self.egress_per_gb * factor)
    }

    pub fn project_storage_month(&self, bytes: i64) -> Dollars {
        let gb = bytes as f64 / 1_000_000_000.0;
        Dollars(gb * self.storage_per_gb_month)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_egress_cost() {
        let m = CostModel {
            egress_per_gb: 0.09,
            storage_per_gb_month: 0.023,
            cache_egress_factor: 1.0,
        };
        let d = m.project_egress(1_000_000_000, false);
        assert!((d.0 - 0.09).abs() < 1e-6);
    }

    #[test]
    fn cache_factor_lowers_cost() {
        let m = CostModel {
            egress_per_gb: 0.09,
            storage_per_gb_month: 0.023,
            cache_egress_factor: 0.0,
        };
        let d = m.project_egress(10_000_000_000, true);
        assert_eq!(d.0, 0.0);
    }
}
