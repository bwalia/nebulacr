//! RPM version comparator (`rpmvercmp` semantics).
//!
//! Reference: `rpmio/rpmvercmp.c` in the `rpm-software-management/rpm`
//! source tree. Ported faithfully; notable rules:
//!
//! * `~` is a pre-release marker. Anything with a leading tilde at the
//!   current position sorts below the same string without it — including
//!   below end-of-string.
//! * `^` is a post-release/build marker. It's *greater than* end-of-string
//!   (so `1.0^build > 1.0`) but *less than* any real token that follows
//!   (so `1.0^build < 1.0.1`).
//! * Otherwise the strings are split into runs of digits and runs of
//!   letters, with other characters acting as separators that don't
//!   participate in ordering. Digit runs compare numerically (leading
//!   zeros stripped, longer run wins). Letter runs compare lexicographically.
//! * When one side yields a digit run and the other yields a letter run at
//!   the same position, the digit run wins — "newer releases are numeric".

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct RpmCompare;

impl VersionCompare for RpmCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        if a.is_empty() || b.is_empty() {
            return Err(VersionError::Invalid("empty rpm version".into()));
        }
        Ok(rpmvercmp(a.as_bytes(), b.as_bytes()))
    }
}

fn rpmvercmp(a: &[u8], b: &[u8]) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let mut i = 0usize;
    let mut j = 0usize;

    loop {
        // Tilde handling: '~' is always less than anything at the same
        // position (including absence).
        let a_t = a.get(i) == Some(&b'~');
        let b_t = b.get(j) == Some(&b'~');
        if a_t || b_t {
            if a_t && !b_t {
                return Ordering::Less;
            }
            if !a_t && b_t {
                return Ordering::Greater;
            }
            i += 1;
            j += 1;
            continue;
        }

        // Caret handling: '^' is greater than end-of-string but less than
        // any real trailing token.
        let a_c = a.get(i) == Some(&b'^');
        let b_c = b.get(j) == Some(&b'^');
        if a_c || b_c {
            if a_c && j >= b.len() {
                return Ordering::Greater;
            }
            if b_c && i >= a.len() {
                return Ordering::Less;
            }
            if a_c && !b_c {
                return Ordering::Less;
            }
            if !a_c && b_c {
                return Ordering::Greater;
            }
            i += 1;
            j += 1;
            continue;
        }

        // Skip non-alphanumeric separators on both sides.
        while i < a.len() && !a[i].is_ascii_alphanumeric() && a[i] != b'~' && a[i] != b'^' {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() && b[j] != b'~' && b[j] != b'^' {
            j += 1;
        }

        if i >= a.len() || j >= b.len() {
            break;
        }

        // Re-check tilde/caret after skipping punctuation.
        if a[i] == b'~' || b[j] == b'~' || a[i] == b'^' || b[j] == b'^' {
            continue;
        }

        // Extract same-kind run from each side.
        let a_is_num = a[i].is_ascii_digit();
        let b_is_num = b[j].is_ascii_digit();

        let a_start = i;
        if a_is_num {
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
        }

        let b_start = j;
        if b_is_num {
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        } else {
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
        }

        // Different kinds → numeric wins.
        if a_is_num != b_is_num {
            return if a_is_num {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let a_seg = &a[a_start..i];
        let b_seg = &b[b_start..j];

        let ord = if a_is_num {
            let a_stripped = strip_leading_zeros(a_seg);
            let b_stripped = strip_leading_zeros(b_seg);
            match a_stripped.len().cmp(&b_stripped.len()) {
                Ordering::Equal => a_stripped.cmp(b_stripped),
                other => other,
            }
        } else {
            a_seg.cmp(b_seg)
        };

        if ord != Ordering::Equal {
            return ord;
        }
    }

    // Remaining bytes: whoever has leftovers wins, unless the leftover is
    // a tilde (pre-release).
    let a_rest = a.get(i).copied();
    let b_rest = b.get(j).copied();
    match (a_rest, b_rest) {
        (None, None) => Ordering::Equal,
        (Some(b'~'), _) => Ordering::Less,
        (_, Some(b'~')) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(_), Some(_)) => Ordering::Equal,
    }
}

fn strip_leading_zeros(mut a: &[u8]) -> &[u8] {
    while a.first() == Some(&b'0') && a.len() > 1 {
        a = &a[1..];
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        RpmCompare.compare(a, b).expect("parse")
    }

    #[test]
    fn equal_strings() {
        assert_eq!(cmp("1.0", "1.0"), Ordering::Equal);
        assert_eq!(cmp("1.0.0", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn simple_numeric() {
        assert_eq!(cmp("1.0", "2.0"), Ordering::Less);
        assert_eq!(cmp("2.0", "1.0"), Ordering::Greater);
        assert_eq!(cmp("1.0.1", "1.0"), Ordering::Greater);
        assert_eq!(cmp("1.10", "1.9"), Ordering::Greater);
    }

    #[test]
    fn alpha_vs_numeric() {
        // numeric segments beat alpha segments
        assert_eq!(cmp("1a", "1.1"), Ordering::Less);
        assert_eq!(cmp("1.1", "1a"), Ordering::Greater);
    }

    #[test]
    fn tilde_pre_release() {
        assert_eq!(cmp("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0", "1.0~rc1"), Ordering::Greater);
        assert_eq!(cmp("1.0~alpha", "1.0~beta"), Ordering::Less);
        assert_eq!(cmp("1.0~~", "1.0~"), Ordering::Less);
    }

    #[test]
    fn caret_build_metadata() {
        // `1.0^build` lies between `1.0` and `1.0.1`
        assert_eq!(cmp("1.0^build1", "1.0"), Ordering::Greater);
        assert_eq!(cmp("1.0^build1", "1.0.1"), Ordering::Less);
        assert_eq!(cmp("1.0^build1", "1.0^build2"), Ordering::Less);
    }

    #[test]
    fn release_separators() {
        // `.` `-` `_` are all separators that don't affect ordering
        assert_eq!(cmp("1.0.1", "1-0-1"), Ordering::Equal);
        assert_eq!(cmp("1_0", "1.0"), Ordering::Equal);
    }

    #[test]
    fn leading_zeros() {
        assert_eq!(cmp("1.007", "1.7"), Ordering::Equal);
        assert_eq!(cmp("1.010", "1.9"), Ordering::Greater);
    }

    #[test]
    fn real_rpm_fixtures() {
        // openssl-1.1.1k-7.el8_6 vs openssl-1.1.1k-8.el8_6
        assert_eq!(cmp("1.1.1k-7.el8_6", "1.1.1k-8.el8_6"), Ordering::Less);
        // glibc-2.28-225.el8 vs glibc-2.28-225.el8_8.6
        assert_eq!(cmp("2.28-225.el8", "2.28-225.el8_8.6"), Ordering::Less);
    }
}
