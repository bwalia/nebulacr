//! semver-based ecosystems (npm, cargo).

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct SemverCompare;

impl VersionCompare for SemverCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let va = semver::Version::parse(a.trim_start_matches('v'))
            .map_err(|e| VersionError::Invalid(format!("{a}: {e}")))?;
        let vb = semver::Version::parse(b.trim_start_matches('v'))
            .map_err(|e| VersionError::Invalid(format!("{b}: {e}")))?;
        Ok(va.cmp(&vb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_semver() {
        let c = SemverCompare;
        assert_eq!(c.compare("1.2.3", "1.2.4").unwrap(), Ordering::Less);
        assert_eq!(c.compare("2.0.0", "1.99.99").unwrap(), Ordering::Greater);
        assert_eq!(c.compare("v1.0.0", "1.0.0").unwrap(), Ordering::Equal);
    }
}
