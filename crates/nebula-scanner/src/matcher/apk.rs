//! Alpine apk-tools version comparator.
//!
//! Grammar (simplified from apk-tools `src/version.c`):
//!
//! ```text
//! version  := <num>(.<num>)* [<letter>] (_<suffix>[<digits>])* [-r<digits>]
//! suffix   := alpha | beta | pre | rc | cvs | svn | git | hg | p
//! ```
//!
//! Ordering rules:
//!
//! * Numeric components compare as integers; a missing component is `0`.
//! * A trailing single letter raises the version above the same numeric tail
//!   without a letter (`1.2` < `1.2a`).
//! * Suffixes have ranks. Pre-release suffixes (`alpha` = −4 … `rc` = −1)
//!   sort below an unsuffixed version; post-release suffixes (`cvs` = 1 …
//!   `p` = 5) sort above it. Missing suffix chain entries compare as
//!   `(rank=0, num=0)`.
//! * `-rN` is the Alpine packaging revision; higher is newer, default `0`.
//!
//! Commit hashes (`~<hex>`) are ignored for ordering — they're rarely
//! present in scanner matcher inputs and apk's own handling of them is
//! lexical on the hex digits, which is not meaningful for CVE matching.

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct ApkCompare;

impl VersionCompare for ApkCompare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let va = ApkVersion::parse(a)?;
        let vb = ApkVersion::parse(b)?;
        Ok(va.cmp(&vb))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ApkVersion {
    numerics: Vec<u64>,
    letter: Option<char>,
    suffixes: Vec<(i32, u64)>,
    revision: u64,
}

impl ApkVersion {
    fn parse(s: &str) -> VersionResult<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(VersionError::Invalid("empty apk version".into()));
        }

        // Split off "-rN" revision (rightmost, only once, digits only).
        let (main, revision) = match s.rfind("-r") {
            Some(idx) if s[idx + 2..].chars().all(|c| c.is_ascii_digit()) => {
                let rev: u64 = s[idx + 2..]
                    .parse()
                    .map_err(|_| VersionError::Invalid(format!("bad apk revision in {s:?}")))?;
                (&s[..idx], rev)
            }
            _ => (s, 0),
        };

        // Drop optional commit hash "~<hex>".
        let main = match main.find('~') {
            Some(i) => &main[..i],
            None => main,
        };

        // Parse numeric(.numeric)*
        let mut chars = main.chars().peekable();
        let mut numerics: Vec<u64> = Vec::new();
        loop {
            let mut digits = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() {
                    digits.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            if digits.is_empty() {
                return Err(VersionError::Invalid(format!(
                    "apk version missing numeric component: {s:?}"
                )));
            }
            let n: u64 = digits
                .parse()
                .map_err(|_| VersionError::Invalid(format!("apk numeric overflow in {s:?}")))?;
            numerics.push(n);
            if chars.peek() == Some(&'.') {
                chars.next();
            } else {
                break;
            }
        }

        // Optional single trailing letter
        let letter = match chars.peek() {
            Some(&c) if c.is_ascii_lowercase() => {
                chars.next();
                Some(c)
            }
            _ => None,
        };

        // _suffix[num] chains
        let mut suffixes: Vec<(i32, u64)> = Vec::new();
        while chars.peek() == Some(&'_') {
            chars.next();
            let mut name = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_lowercase() {
                    name.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            let rank = suffix_rank(&name).ok_or_else(|| {
                VersionError::Invalid(format!("unknown apk suffix {name:?} in {s:?}"))
            })?;
            let mut digits = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() {
                    digits.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            let num: u64 = if digits.is_empty() {
                0
            } else {
                digits
                    .parse()
                    .map_err(|_| VersionError::Invalid(format!("apk suffix num in {s:?}")))?
            };
            suffixes.push((rank, num));
        }

        if chars.peek().is_some() {
            return Err(VersionError::Invalid(format!(
                "trailing garbage in apk version {s:?}"
            )));
        }

        Ok(Self {
            numerics,
            letter,
            suffixes,
            revision,
        })
    }
}

impl Ord for ApkVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.numerics.len().max(other.numerics.len());
        for i in 0..n {
            let a = self.numerics.get(i).copied().unwrap_or(0);
            let b = other.numerics.get(i).copied().unwrap_or(0);
            if a != b {
                return a.cmp(&b);
            }
        }
        if self.letter != other.letter {
            return self.letter.cmp(&other.letter);
        }
        let sn = self.suffixes.len().max(other.suffixes.len());
        for i in 0..sn {
            let a = self.suffixes.get(i).copied().unwrap_or((0, 0));
            let b = other.suffixes.get(i).copied().unwrap_or((0, 0));
            if a != b {
                return a.cmp(&b);
            }
        }
        self.revision.cmp(&other.revision)
    }
}

impl PartialOrd for ApkVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn suffix_rank(s: &str) -> Option<i32> {
    match s {
        "alpha" => Some(-4),
        "beta" => Some(-3),
        "pre" => Some(-2),
        "rc" => Some(-1),
        "cvs" => Some(1),
        "svn" => Some(2),
        "git" => Some(3),
        "hg" => Some(4),
        "p" => Some(5),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        ApkCompare.compare(a, b).expect("parse")
    }

    #[test]
    fn simple_numeric() {
        assert_eq!(cmp("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(cmp("1.2.10", "1.2.9"), Ordering::Greater);
        assert_eq!(cmp("1.2", "1.2.0"), Ordering::Equal);
    }

    #[test]
    fn revision_moves_version() {
        assert_eq!(cmp("1.2.3-r0", "1.2.3-r1"), Ordering::Less);
        assert_eq!(cmp("1.2.3-r5", "1.2.3-r5"), Ordering::Equal);
        assert_eq!(cmp("1.2.12-r3", "1.3.2-r0"), Ordering::Less);
    }

    #[test]
    fn trailing_letter_greater_than_none() {
        assert_eq!(cmp("1.2", "1.2a"), Ordering::Less);
        assert_eq!(cmp("1.2a", "1.2b"), Ordering::Less);
    }

    #[test]
    fn pre_release_suffix_less_than_release() {
        assert_eq!(cmp("1.0_alpha", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0_alpha", "1.0_beta"), Ordering::Less);
        assert_eq!(cmp("1.0_beta", "1.0_pre"), Ordering::Less);
        assert_eq!(cmp("1.0_pre", "1.0_rc"), Ordering::Less);
        assert_eq!(cmp("1.0_rc", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0_rc1", "1.0_rc2"), Ordering::Less);
    }

    #[test]
    fn post_release_suffix_greater_than_release() {
        assert_eq!(cmp("1.0", "1.0_cvs"), Ordering::Less);
        assert_eq!(cmp("1.0_cvs", "1.0_svn"), Ordering::Less);
        assert_eq!(cmp("1.0_svn", "1.0_git"), Ordering::Less);
        assert_eq!(cmp("1.0_git", "1.0_hg"), Ordering::Less);
        assert_eq!(cmp("1.0_hg", "1.0_p"), Ordering::Less);
        assert_eq!(cmp("1.0_p1", "1.0_p2"), Ordering::Less);
    }

    #[test]
    fn hash_ignored() {
        assert_eq!(cmp("1.2.3~abcdef", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn rejects_garbage() {
        assert!(ApkCompare.compare("not-a-version", "1").is_err());
        assert!(ApkCompare.compare("1.2.3x!", "1.2.3").is_err());
    }

    #[test]
    fn alpine_zlib_fix_range() {
        // Real CVE-2022-37434 fix: zlib 1.2.12-r3 -> 1.2.13-r0.
        assert_eq!(cmp("1.2.12-r3", "1.2.13-r0"), Ordering::Less);
    }
}
