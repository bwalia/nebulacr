//! apk version comparator — stub (task #8).

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct ApkCompare;

impl VersionCompare for ApkCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let _ = (a, b);
        Err(VersionError::Invalid("apk compare not implemented".into()))
    }
}
