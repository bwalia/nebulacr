//! Shared CVSS / severity helpers.
//!
//! Used by both the online OSV client and the offline ingesters that
//! populate our own vuln DB. Extracted so both paths classify the same
//! vector into the same `Severity` bucket.

use crate::model::Severity;

/// Extract a base score from an OSV-style severity `score`.
///
/// OSV encodes the score either as a literal float (rare) or as a CVSS vector
/// string like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (common). We
/// accept both and compute the CVSS v3 base score from the vector per the
/// CVSS 3.1 specification.
pub fn parse_cvss_base(s: &str) -> Option<f64> {
    if let Ok(v) = s.parse::<f64>() {
        return Some(v);
    }
    if s.starts_with("CVSS:3") {
        return cvss3_base(s);
    }
    None
}

/// CVSS v3/v3.1 base-score calculator. Returns None if required metrics are
/// missing or the vector is malformed.
pub fn cvss3_base(vector: &str) -> Option<f64> {
    let mut av = None;
    let mut ac = None;
    let mut pr_raw = None;
    let mut ui = None;
    let mut scope = None;
    let mut c_m = None;
    let mut i_m = None;
    let mut a_m = None;

    for tok in vector.split('/').skip(1) {
        let (k, v) = tok.split_once(':')?;
        match k {
            "AV" => {
                av = match v {
                    "N" => Some(0.85),
                    "A" => Some(0.62),
                    "L" => Some(0.55),
                    "P" => Some(0.20),
                    _ => None,
                }
            }
            "AC" => {
                ac = match v {
                    "L" => Some(0.77),
                    "H" => Some(0.44),
                    _ => None,
                }
            }
            "PR" => pr_raw = Some(v.to_string()),
            "UI" => {
                ui = match v {
                    "N" => Some(0.85),
                    "R" => Some(0.62),
                    _ => None,
                }
            }
            "S" => scope = Some(v.to_string()),
            "C" => c_m = impact_metric(v),
            "I" => i_m = impact_metric(v),
            "A" => a_m = impact_metric(v),
            _ => {}
        }
    }

    let av = av?;
    let ac = ac?;
    let ui = ui?;
    let scope = scope?;
    let c = c_m?;
    let i = i_m?;
    let a = a_m?;
    let pr_raw = pr_raw?;

    let scope_changed = scope == "C";
    let pr = if scope_changed {
        match pr_raw.as_str() {
            "N" => 0.85,
            "L" => 0.68,
            "H" => 0.50,
            _ => return None,
        }
    } else {
        match pr_raw.as_str() {
            "N" => 0.85,
            "L" => 0.62,
            "H" => 0.27,
            _ => return None,
        }
    };

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if scope_changed {
        ((impact + exploitability) * 1.08).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(roundup_cvss(base))
}

fn impact_metric(v: &str) -> Option<f64> {
    match v {
        "N" => Some(0.0),
        "L" => Some(0.22),
        "H" => Some(0.56),
        _ => None,
    }
}

/// CVSS "roundup" — round up to one decimal place.
fn roundup_cvss(x: f64) -> f64 {
    let scaled = (x * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        (scaled / 10_000) as f64 / 10.0
    } else {
        (((scaled / 10_000) + 1) as f64) / 10.0
    }
}

pub fn classify(score: Option<f64>) -> Severity {
    match score {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::High,
        Some(s) if s >= 4.0 => Severity::Medium,
        Some(s) if s > 0.0 => Severity::Low,
        _ => Severity::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_buckets() {
        assert!(matches!(classify(Some(9.8)), Severity::Critical));
        assert!(matches!(classify(Some(7.5)), Severity::High));
        assert!(matches!(classify(Some(5.0)), Severity::Medium));
        assert!(matches!(classify(Some(2.0)), Severity::Low));
        assert!(matches!(classify(None), Severity::Unknown));
    }

    #[test]
    fn cvss_vector_critical() {
        let s = parse_cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").unwrap();
        assert!((s - 10.0).abs() < 0.05, "got {s}");
    }

    #[test]
    fn cvss_vector_high() {
        let s = parse_cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H").unwrap();
        assert!((s - 7.5).abs() < 0.05, "got {s}");
    }

    #[test]
    fn cvss_vector_medium() {
        let s = parse_cvss_base("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N").unwrap();
        assert!(s >= 4.0 && s < 7.0, "got {s}");
    }

    #[test]
    fn cvss_literal_float_still_accepted() {
        assert_eq!(parse_cvss_base("9.8").unwrap(), 9.8);
    }
}
