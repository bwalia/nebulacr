//! Go module version comparator.
//!
//! Go module versions are semver with a mandatory leading `v`, plus two
//! Go-specific twists:
//!
//! * Pseudo-versions — `v0.0.0-20200101000000-abcdef12345` — are already
//!   valid semver because the date-commit tail lives in the pre-release
//!   slot, so ordinary semver ordering Just Works.
//! * `+incompatible` is a build-metadata marker Go uses for pre-module
//!   `v2+` releases. Semver says build metadata is ignored for ordering,
//!   which matches Go's behaviour; we strip the suffix before parsing so
//!   the semver crate can accept versions like `v2.0.0+incompatible`.
//!
//! Missing trailing segments (`v1.2`, `v1`) are padded with zeros. This is
//! a lenience the Go toolchain does *not* grant — it's here so that mildly
//! malformed "fixed" versions coming from upstream advisories still match.

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct GoCompare;

impl VersionCompare for GoCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let va = parse(a)?;
        let vb = parse(b)?;
        Ok(va.cmp(&vb))
    }
}

fn parse(s: &str) -> VersionResult<semver::Version> {
    let s = s.trim();
    if s.is_empty() {
        return Err(VersionError::Invalid("empty go version".into()));
    }
    let s = s.strip_prefix('v').unwrap_or(s);
    let s = s
        .strip_suffix("+incompatible")
        .map(|x| x.to_string())
        .unwrap_or_else(|| s.to_string());

    let normalized = pad_to_three(&s);
    semver::Version::parse(&normalized)
        .map_err(|e| VersionError::Invalid(format!("go version {s:?}: {e}")))
}

fn pad_to_three(s: &str) -> String {
    // Find the end of the X(.Y)*(.Z) core — first '-' or '+'.
    let cut = s.find(['-', '+']).unwrap_or(s.len());
    let (core, tail) = s.split_at(cut);
    let dots = core.chars().filter(|c| *c == '.').count();
    match dots {
        0 => format!("{core}.0.0{tail}"),
        1 => format!("{core}.0{tail}"),
        _ => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        GoCompare.compare(a, b).expect("parse")
    }

    #[test]
    fn simple_semver() {
        assert_eq!(cmp("v1.2.3", "v1.2.3"), Ordering::Equal);
        assert_eq!(cmp("v1.2.3", "v1.2.4"), Ordering::Less);
        assert_eq!(cmp("v1.10.0", "v1.9.0"), Ordering::Greater);
    }

    #[test]
    fn leading_v_optional() {
        assert_eq!(cmp("v1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn pseudo_versions() {
        // Pre-release slot orders lexically after semver normalization.
        assert_eq!(
            cmp(
                "v0.0.0-20200101000000-aaaaaaaaaaaa",
                "v0.0.0-20210101000000-bbbbbbbbbbbb"
            ),
            Ordering::Less
        );
        // Pseudo-version < tagged release with same base.
        assert_eq!(
            cmp("v0.0.0-20200101000000-abcdef12345", "v0.0.1"),
            Ordering::Less
        );
    }

    #[test]
    fn incompatible_suffix_ignored() {
        assert_eq!(cmp("v2.0.0+incompatible", "v2.0.0"), Ordering::Equal);
        assert_eq!(cmp("v2.0.0+incompatible", "v2.0.1"), Ordering::Less);
    }

    #[test]
    fn padding_short_forms() {
        assert_eq!(cmp("v1.2", "v1.2.0"), Ordering::Equal);
        assert_eq!(cmp("v1", "v1.0.0"), Ordering::Equal);
        assert_eq!(cmp("v1", "v1.0.1"), Ordering::Less);
    }

    #[test]
    fn pre_release_below_release() {
        assert_eq!(cmp("v1.0.0-rc1", "v1.0.0"), Ordering::Less);
        assert_eq!(cmp("v1.0.0-alpha", "v1.0.0-beta"), Ordering::Less);
    }

    #[test]
    fn rejects_garbage() {
        assert!(GoCompare.compare("", "v1.0.0").is_err());
        assert!(GoCompare.compare("vNOTAVERSION", "v1.0.0").is_err());
    }
}
