//! go version comparator — stub (task #8).

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct GoCompare;

impl VersionCompare for GoCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let _ = (a, b);
        Err(VersionError::Invalid("go compare not implemented".into()))
    }
}
