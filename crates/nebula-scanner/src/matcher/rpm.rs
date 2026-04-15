//! rpm version comparator — stub (task #8).

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct RpmCompare;

impl VersionCompare for RpmCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let _ = (a, b);
        Err(VersionError::Invalid("rpm compare not implemented".into()))
    }
}
