//! Ecosystem-aware version comparators. Used by `NebulaVulnDb::query` to
//! decide whether an installed package version falls inside a vuln's
//! affected range.
//!
//! Task #8 fills in each comparator with fixture tests. For now the trait
//! is defined so callers compile against the eventual API.

pub mod apk;
pub mod deb;
pub mod go;
pub mod pep440;
pub mod rpm;
pub mod semver_ecosystem;

use std::cmp::Ordering;

#[derive(Debug, thiserror::Error)]
pub enum VersionError {
    #[error("invalid version string: {0}")]
    Invalid(String),
}

pub type VersionResult<T> = std::result::Result<T, VersionError>;

pub trait VersionCompare: Send + Sync {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering>;
}

pub fn for_ecosystem(ecosystem: &str) -> Option<Box<dyn VersionCompare>> {
    match ecosystem {
        "npm" | "cargo" => Some(Box::new(semver_ecosystem::SemverCompare)),
        "deb" => Some(Box::new(deb::DebCompare)),
        "rpm" => Some(Box::new(rpm::RpmCompare)),
        "apk" => Some(Box::new(apk::ApkCompare)),
        "pypi" => Some(Box::new(pep440::Pep440Compare)),
        "go" => Some(Box::new(go::GoCompare)),
        _ => None,
    }
}
