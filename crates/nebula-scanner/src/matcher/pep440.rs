//! PEP 440 (Python) version comparator.
//!
//! Implements the ordering rules from PEP 440 sufficiently for CVE range
//! matching. A version is parsed into:
//!
//! ```text
//! [N!]<release>[(a|b|rc)N][.postN][.devN][+local]
//! ```
//!
//! and compared using a sort key that reproduces PEP 440's three tricky
//! corners: (a) dev-only releases sort below any pre-release of the same
//! base, (b) no pre-release sorts above any pre-release, (c) no dev sorts
//! above any dev release. Local version labels (the `+<local>` tail) are
//! ignored for comparison — they only matter as a tie-breaker between
//! otherwise-identical versions, which does not affect vuln matching.
//!
//! Accepted synonyms follow PyPA's `packaging` library: `alpha`→`a`,
//! `beta`→`b`, `c`/`pre`/`preview`→`rc`, `rev`/`r`→`post`. Separators
//! `.`, `-`, `_` between components are all accepted. A leading `v` is
//! stripped.

use std::cmp::Ordering;

use super::{VersionCompare, VersionError, VersionResult};

pub struct Pep440Compare;

impl VersionCompare for Pep440Compare {
    fn compare(&self, a: &str, b: &str) -> VersionResult<Ordering> {
        let va = Pep440Version::parse(a)?;
        let vb = Pep440Version::parse(b)?;
        Ok(va.key().cmp(&vb.key()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pep440Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(PreKind, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PreKind {
    Alpha,
    Beta,
    Rc,
}

// (epoch, release, pre-key, post-key, dev-key).
// Each sub-tuple carries a presence flag in its first field so that
// "no pre-release" / "no post" / "no dev" can be placed correctly
// relative to labelled versions (see `Pep440Version::key`).
type SortKey = (u64, Vec<u64>, (i8, u8, u64), (i8, u64), (i8, u64));

impl Pep440Version {
    fn parse(s: &str) -> VersionResult<Self> {
        let raw = s.trim().to_ascii_lowercase();
        let s = raw.strip_prefix('v').unwrap_or(&raw);
        if s.is_empty() {
            return Err(VersionError::Invalid("empty pep440 version".into()));
        }

        // Drop local label if present — ignored for ordering.
        let s = match s.find('+') {
            Some(i) => &s[..i],
            None => s,
        };

        // Epoch (`N!`)
        let (epoch, rest) = match s.find('!') {
            Some(i) => {
                let e: u64 = s[..i]
                    .parse()
                    .map_err(|_| VersionError::Invalid(format!("pep440 bad epoch in {s:?}")))?;
                (e, &s[i + 1..])
            }
            None => (0, s),
        };

        // Release: digits('.'digits)*
        let mut release = Vec::new();
        let mut rest = rest;
        loop {
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            if end == 0 {
                return Err(VersionError::Invalid(format!(
                    "pep440 missing release digits in {s:?}"
                )));
            }
            let n: u64 = rest[..end]
                .parse()
                .map_err(|_| VersionError::Invalid(format!("pep440 release overflow in {s:?}")))?;
            release.push(n);
            rest = &rest[end..];
            if rest.starts_with('.') && rest[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                rest = &rest[1..];
            } else {
                break;
            }
        }

        // Implicit post-release form: `-<digits>` directly after the
        // release, with no pre/post/dev label. Must be checked before
        // consume_sep would eat the leading '-'.
        let mut post: Option<u64> = None;
        if let Some((n, after)) = match_implicit_post(rest) {
            post = Some(n);
            rest = after;
        }

        rest = consume_sep(rest);

        // Pre-release
        let mut pre: Option<(PreKind, u64)> = None;
        if let Some((kind, after)) = match_pre_label(rest) {
            let after = consume_sep(after);
            let (n, after) = parse_optional_digits(after);
            pre = Some((kind, n));
            rest = after;
        }

        rest = consume_sep(rest);

        // Explicit post-release: `.postN`, `.revN`, `.rN`.
        if post.is_none()
            && let Some(after) = match_post_label(rest)
        {
            let after = consume_sep(after);
            let (n, after) = parse_optional_digits(after);
            post = Some(n);
            rest = after;
        }

        rest = consume_sep(rest);

        // Dev-release: ".dev N"
        let mut dev: Option<u64> = None;
        if let Some(after) = rest.strip_prefix("dev") {
            let after = consume_sep(after);
            let (n, after) = parse_optional_digits(after);
            dev = Some(n);
            rest = after;
        }

        rest = consume_sep(rest);

        if !rest.is_empty() {
            return Err(VersionError::Invalid(format!(
                "trailing garbage in pep440 version {s:?}: {rest:?}"
            )));
        }

        Ok(Self {
            epoch,
            release,
            pre,
            post,
            dev,
        })
    }

    /// Build the PEP 440 sort key (epoch, release, pre-key, post-key, dev-key).
    /// Trailing zeros in `release` are trimmed so `1.0 == 1.0.0`.
    fn key(&self) -> SortKey {
        let mut rel = self.release.clone();
        while rel.len() > 1 && *rel.last().unwrap() == 0 {
            rel.pop();
        }

        // Pre-key. Three buckets:
        //   dev-only (pre=None, post=None, dev=Some) → -1: sorts below any pre
        //   normal pre (pre=Some)                    →  0: order by (kind, n)
        //   otherwise                                →  1: sorts above any pre
        let pre_key: (i8, u8, u64) = match (&self.pre, &self.post, &self.dev) {
            (None, None, Some(_)) => (-1, 0, 0),
            (Some((kind, n)), _, _) => (0, *kind as u8, *n),
            _ => (1, 0, 0),
        };

        // Post-key: no post sorts below any post.
        let post_key: (i8, u64) = match self.post {
            Some(n) => (1, n),
            None => (-1, 0),
        };

        // Dev-key: no dev sorts above any dev (dev is "not yet finished").
        let dev_key: (i8, u64) = match self.dev {
            Some(n) => (0, n),
            None => (1, 0),
        };

        (self.epoch, rel, pre_key, post_key, dev_key)
    }
}

fn consume_sep(s: &str) -> &str {
    s.strip_prefix(['.', '-', '_']).unwrap_or(s)
}

fn match_pre_label(s: &str) -> Option<(PreKind, &str)> {
    // Ordered longest-first to avoid prefix ambiguity (e.g. "alpha" before "a").
    for (lit, kind) in &[
        ("alpha", PreKind::Alpha),
        ("preview", PreKind::Rc),
        ("beta", PreKind::Beta),
        ("pre", PreKind::Rc),
        ("rc", PreKind::Rc),
        ("c", PreKind::Rc),
        ("a", PreKind::Alpha),
        ("b", PreKind::Beta),
    ] {
        if let Some(rest) = s.strip_prefix(lit) {
            return Some((*kind, rest));
        }
    }
    None
}

fn match_post_label(s: &str) -> Option<&str> {
    for lit in &["post", "rev", "r"] {
        if let Some(rest) = s.strip_prefix(lit) {
            return Some(rest);
        }
    }
    None
}

/// Implicit post form: `-<digits>` directly after the release.
/// Must not collide with dev ("-dev…") or with post ("-post…", "-r…")
/// which match_post_label handles explicitly.
fn match_implicit_post(s: &str) -> Option<(u64, &str)> {
    let rest = s.strip_prefix('-')?;
    if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let n: u64 = rest[..end].parse().ok()?;
        Some((n, &rest[end..]))
    } else {
        None
    }
}

fn parse_optional_digits(s: &str) -> (u64, &str) {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return (0, s);
    }
    (s[..end].parse().unwrap_or(0), &s[end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        Pep440Compare.compare(a, b).expect("parse")
    }

    #[test]
    fn release_only() {
        assert_eq!(cmp("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(cmp("1.0", "1.1"), Ordering::Less);
        assert_eq!(cmp("1.2", "1.10"), Ordering::Less);
    }

    #[test]
    fn pre_release_ordering() {
        // PEP 440 canonical order: dev < a < b < rc < release < post
        assert_eq!(cmp("1.0a1", "1.0a2"), Ordering::Less);
        assert_eq!(cmp("1.0a1", "1.0b1"), Ordering::Less);
        assert_eq!(cmp("1.0b1", "1.0rc1"), Ordering::Less);
        assert_eq!(cmp("1.0rc1", "1.0"), Ordering::Less);
        assert_eq!(cmp("1.0", "1.0.post1"), Ordering::Less);
    }

    #[test]
    fn dev_before_pre() {
        // Dev-only sorts below any pre-release.
        assert_eq!(cmp("1.0.dev1", "1.0a1"), Ordering::Less);
        // But "1.0a1.dev1" is a dev build of 1.0a1, so < 1.0a1.
        assert_eq!(cmp("1.0a1.dev1", "1.0a1"), Ordering::Less);
        assert_eq!(cmp("1.0a1.dev1", "1.0a2"), Ordering::Less);
    }

    #[test]
    fn post_release_ordering() {
        assert_eq!(cmp("1.0.post1", "1.0.post2"), Ordering::Less);
        assert_eq!(cmp("1.0.post1", "1.0.post1.dev1"), Ordering::Greater);
        // 1.0.post1.dev1 is dev of post1, less than post1, greater than 1.0
        assert_eq!(cmp("1.0", "1.0.post1.dev1"), Ordering::Less);
    }

    #[test]
    fn synonyms() {
        // alpha == a, beta == b, c/pre/preview == rc
        assert_eq!(cmp("1.0alpha1", "1.0a1"), Ordering::Equal);
        assert_eq!(cmp("1.0beta1", "1.0b1"), Ordering::Equal);
        assert_eq!(cmp("1.0c1", "1.0rc1"), Ordering::Equal);
        assert_eq!(cmp("1.0pre1", "1.0rc1"), Ordering::Equal);
        assert_eq!(cmp("1.0preview1", "1.0rc1"), Ordering::Equal);
    }

    #[test]
    fn epoch_dominates() {
        assert_eq!(cmp("1!1.0", "2.0"), Ordering::Greater);
        assert_eq!(cmp("0!1.0", "1.0"), Ordering::Equal);
    }

    #[test]
    fn separators_and_prefix() {
        assert_eq!(cmp("v1.0", "1.0"), Ordering::Equal);
        assert_eq!(cmp("1.0-a1", "1.0a1"), Ordering::Equal);
        assert_eq!(cmp("1.0_a1", "1.0.a1"), Ordering::Equal);
    }

    #[test]
    fn implicit_post() {
        // `1.0-1` is implicit post-release: equal to `1.0.post1`
        assert_eq!(cmp("1.0-1", "1.0.post1"), Ordering::Equal);
    }

    #[test]
    fn local_ignored() {
        // `+local` is ignored for ordering.
        assert_eq!(cmp("1.0+deadbeef", "1.0"), Ordering::Equal);
        assert_eq!(cmp("1.0+abc", "1.0+xyz"), Ordering::Equal);
    }

    #[test]
    fn real_pypi_fixtures() {
        // Flask 2.0.1 < 2.0.2
        assert_eq!(cmp("2.0.1", "2.0.2"), Ordering::Less);
        // requests 2.28.0a1 < 2.28.0
        assert_eq!(cmp("2.28.0a1", "2.28.0"), Ordering::Less);
        // numpy 1.21.0rc1 < 1.21.0
        assert_eq!(cmp("1.21.0rc1", "1.21.0"), Ordering::Less);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Pep440Compare.compare("", "1").is_err());
        assert!(Pep440Compare.compare("not.a.version!!", "1").is_err());
    }
}
