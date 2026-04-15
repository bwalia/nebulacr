//! deb version comparator — stub (task #8).

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct DebCompare;

impl VersionCompare for DebCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let _ = (a, b);
        Err(VersionError::Invalid("deb compare not implemented".into()))
    }
}
