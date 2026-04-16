//! Debian dpkg version comparator.
//!
//! Grammar: `[epoch:]upstream_version[-debian_revision]`.
//!
//! Each component is compared with the dpkg ordering rule: zip through
//! both strings, alternating non-digit and digit runs.
//!
//! * In a non-digit run, `~` sorts *below* an empty string, an empty string
//!   sorts below letters, and letters sort below all other printable
//!   characters. Within each class, ASCII order applies.
//! * In a digit run, both runs are compared as base-10 integers with
//!   leading zeros stripped (length first, then lex — keeps the
//!   comparison overflow-free for arbitrarily long numbers).
//!
//! This matches the algorithm documented in `deb-version(5)` and
//! implemented by `dpkg --compare-versions`.

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct DebCompare;

impl VersionCompare for DebCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let va = DebVersion::parse(a)?;
        let vb = DebVersion::parse(b)?;
        Ok(va.cmp(&vb))
    }
}

#[derive(Debug)]
struct DebVersion<'a> {
    epoch: u64,
    upstream: &'a str,
    revision: &'a str,
}

impl<'a> DebVersion<'a> {
    fn parse(s: &'a str) -> VersionResult<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(VersionError::Invalid("empty deb version".into()));
        }

        let (epoch, rest) = match s.find(':') {
            Some(idx) if !s[..idx].is_empty() && s[..idx].chars().all(|c| c.is_ascii_digit()) => {
                let e: u64 = s[..idx]
                    .parse()
                    .map_err(|_| VersionError::Invalid(format!("deb epoch overflow in {s:?}")))?;
                (e, &s[idx + 1..])
            }
            _ => (0, s),
        };

        let (upstream, revision) = match rest.rfind('-') {
            Some(idx) => (&rest[..idx], &rest[idx + 1..]),
            None => (rest, ""),
        };

        if upstream.is_empty() {
            return Err(VersionError::Invalid(format!(
                "deb upstream empty in {s:?}"
            )));
        }

        Ok(Self {
            epoch,
            upstream,
            revision,
        })
    }

    fn cmp(&self, other: &Self) -> Ordering {
        match self.epoch.cmp(&other.epoch) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match compare_component(self.upstream, other.upstream) {
            Ordering::Equal => {}
            ord => return ord,
        }
        compare_component(self.revision, other.revision)
    }
}

fn compare_component(a: &str, b: &str) -> Ordering {
    let mut ai = a.as_bytes();
    let mut bi = b.as_bytes();
    loop {
        let a_nondigit = take_while(&mut ai, |b| !b.is_ascii_digit());
        let b_nondigit = take_while(&mut bi, |b| !b.is_ascii_digit());
        match compare_non_digit(a_nondigit, b_nondigit) {
            Ordering::Equal => {}
            ord => return ord,
        }
        let a_digit = take_while(&mut ai, |b| b.is_ascii_digit());
        let b_digit = take_while(&mut bi, |b| b.is_ascii_digit());
        match compare_digit(a_digit, b_digit) {
            Ordering::Equal => {}
            ord => return ord,
        }
        if ai.is_empty() && bi.is_empty() {
            return Ordering::Equal;
        }
    }
}

fn take_while<'a>(buf: &mut &'a [u8], pred: impl Fn(u8) -> bool) -> &'a [u8] {
    let end = buf.iter().copied().take_while(|b| pred(*b)).count();
    let (head, tail) = buf.split_at(end);
    *buf = tail;
    head
}

fn compare_non_digit(a: &[u8], b: &[u8]) -> Ordering {
    let len = a.len().max(b.len());
    for i in 0..len {
        let av = nondigit_rank(a.get(i).copied());
        let bv = nondigit_rank(b.get(i).copied());
        if av != bv {
            return av.cmp(&bv);
        }
    }
    Ordering::Equal
}

/// Rank rule: `~` < end-of-string < letters < other printable.
/// Within each class, ASCII code point ordering is preserved.
fn nondigit_rank(b: Option<u8>) -> i32 {
    match b {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_alphabetic() => 256 + c as i32,
        Some(c) => 512 + c as i32,
    }
}

fn compare_digit(a: &[u8], b: &[u8]) -> Ordering {
    // strip leading zeros
    let a = strip_leading_zeros(a);
    let b = strip_leading_zeros(b);
    match a.len().cmp(&b.len()) {
        Ordering::Equal => a.cmp(b),
        ord => ord,
    }
}

fn strip_leading_zeros(mut a: &[u8]) -> &[u8] {
    while a.first() == Some(&b'0') {
        a = &a[1..];
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        DebCompare.compare(a, b).expect("parse")
    }

    #[test]
    fn simple_numeric() {
        assert_eq!(cmp("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(cmp("1.2.10", "1.2.9"), Ordering::Greater);
    }

    #[test]
    fn debian_revision() {
        assert_eq!(cmp("1.2.3-1", "1.2.3-2"), Ordering::Less);
        assert_eq!(cmp("1.2.3-1", "1.2.3-1ubuntu1"), Ordering::Less);
        assert_eq!(cmp("1.2.3", "1.2.3-1"), Ordering::Less);
    }

    #[test]
    fn epoch_dominates() {
        assert_eq!(cmp("1:0.1", "2.0"), Ordering::Greater);
        assert_eq!(cmp("2:1.0", "1:9.9"), Ordering::Greater);
        assert_eq!(cmp("0:1.0", "1.0"), Ordering::Equal);
    }

    #[test]
    fn tilde_is_pre_release() {
        assert_eq!(cmp("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0~alpha", "1.0~beta"), Ordering::Less);
        assert_eq!(cmp("1.0~~", "1.0~"), Ordering::Less);
        assert_eq!(cmp("1.0~", "1.0"), Ordering::Less);
    }

    #[test]
    fn leading_zeros_ignored() {
        assert_eq!(cmp("1.007", "1.7"), Ordering::Equal);
        assert_eq!(cmp("1.010", "1.9"), Ordering::Greater);
    }

    #[test]
    fn letter_beats_non_letter() {
        // "1.0a" vs "1.0.1": at position 3, 'a' is letter (rank 256+97), '.' is non-letter (rank 512+46)
        // so "1.0a" < "1.0.1" because letters sort before non-letters.
        assert_eq!(cmp("1.0a", "1.0.1"), Ordering::Less);
    }

    #[test]
    fn dpkg_reference_vectors() {
        // Sourced from Debian Policy §5.6.12 and `dpkg --compare-versions`.
        assert_eq!(
            cmp("7.4.052-1ubuntu3", "7.4.052-1ubuntu3.1"),
            Ordering::Less
        );
        assert_eq!(cmp("1:1.2.3-1", "1.2.3-1"), Ordering::Greater);
        assert_eq!(
            cmp("2.30-21ubuntu1~20.04.7", "2.30-21ubuntu1~20.04.8"),
            Ordering::Less
        );
    }

    #[test]
    fn rejects_empty() {
        assert!(DebCompare.compare("", "1.0").is_err());
    }
}
