//! pep440 version comparator — stub (task #8).

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct Pep440Compare;

impl VersionCompare for Pep440Compare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let _ = (a, b);
        Err(VersionError::Invalid("pep440 compare not implemented".into()))
    }
}
