//! TTL header parsing. Accepted formats:
//!
//! - Duration: `7d`, `12h`, `30m`, `300s`
//! - Absolute RFC 3339: `2026-06-01T00:00:00Z`
//!
//! Returned as a `TtlSpec` carrying the absolute expiry time so the
//! caller never has to re-parse.

use chrono::{DateTime, Duration, Utc};

#[derive(Debug, Clone, Copy)]
pub struct TtlSpec {
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum TtlError {
    #[error("empty TTL value")]
    Empty,
    #[error("invalid TTL: {0}")]
    Invalid(String),
}

pub fn parse_ttl_header(now: DateTime<Utc>, raw: &str) -> Result<TtlSpec, TtlError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(TtlError::Empty);
    }

    // Absolute RFC 3339?
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(TtlSpec {
            expires_at: dt.with_timezone(&Utc),
        });
    }

    // Duration suffix.
    let (num_part, suffix) = raw.split_at(
        raw.find(|c: char| !c.is_ascii_digit() && c != '-')
            .ok_or_else(|| TtlError::Invalid(raw.into()))?,
    );
    let n: i64 = num_part
        .parse()
        .map_err(|_| TtlError::Invalid(raw.into()))?;
    if n < 0 {
        return Err(TtlError::Invalid(format!("negative TTL: {raw}")));
    }
    let dur = match suffix {
        "s" => Duration::seconds(n),
        "m" => Duration::minutes(n),
        "h" => Duration::hours(n),
        "d" => Duration::days(n),
        "w" => Duration::weeks(n),
        other => return Err(TtlError::Invalid(format!("unknown unit: {other}"))),
    };
    Ok(TtlSpec {
        expires_at: now + dur,
    })
}

/// Cap a TTL to the project's `max_ttl_secs`. Returns `(capped_spec, was_capped)`.
pub fn cap_ttl(spec: TtlSpec, now: DateTime<Utc>, max_secs: i64) -> (TtlSpec, bool) {
    let max = now + Duration::seconds(max_secs);
    if spec.expires_at > max {
        (TtlSpec { expires_at: max }, true)
    } else {
        (spec, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration_suffixes() {
        let now = DateTime::parse_from_rfc3339("2026-05-13T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let spec = parse_ttl_header(now, "7d").unwrap();
        assert_eq!(spec.expires_at, now + Duration::days(7));

        let spec = parse_ttl_header(now, "12h").unwrap();
        assert_eq!(spec.expires_at, now + Duration::hours(12));

        let spec = parse_ttl_header(now, "30m").unwrap();
        assert_eq!(spec.expires_at, now + Duration::minutes(30));
    }

    #[test]
    fn parses_rfc3339_absolute() {
        let now = DateTime::parse_from_rfc3339("2026-05-13T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let spec = parse_ttl_header(now, "2026-06-01T00:00:00Z").unwrap();
        assert_eq!(
            spec.expires_at,
            DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn rejects_negative_ttl() {
        let now = Utc::now();
        let err = parse_ttl_header(now, "-7d").unwrap_err();
        matches!(err, TtlError::Invalid(_));
    }

    #[test]
    fn rejects_unknown_unit() {
        let now = Utc::now();
        let err = parse_ttl_header(now, "7y").unwrap_err();
        matches!(err, TtlError::Invalid(_));
    }

    #[test]
    fn rejects_empty() {
        let now = Utc::now();
        let err = parse_ttl_header(now, "").unwrap_err();
        matches!(err, TtlError::Empty);
    }

    #[test]
    fn cap_ttl_caps_when_over_max() {
        let now = Utc::now();
        let big = TtlSpec {
            expires_at: now + Duration::days(30),
        };
        let (capped, was_capped) = cap_ttl(big, now, 7 * 86400);
        assert!(was_capped);
        assert_eq!(capped.expires_at, now + Duration::seconds(7 * 86400));
    }

    #[test]
    fn cap_ttl_preserves_when_under_max() {
        let now = Utc::now();
        let small = TtlSpec {
            expires_at: now + Duration::days(3),
        };
        let (capped, was_capped) = cap_ttl(small, now, 7 * 86400);
        assert!(!was_capped);
        assert_eq!(capped.expires_at, small.expires_at);
    }
}
