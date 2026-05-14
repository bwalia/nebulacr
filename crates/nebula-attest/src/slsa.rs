//! SLSA-level inference from a SLSA Provenance v1 predicate.
//!
//! Slice 1: a conservative classifier that reads only the runDetails
//! shape and the builder.id. Real-world heuristics (Fulcio root match,
//! material existence verification) come in slice 2.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlsaLevel {
    L0 = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
}

impl SlsaLevel {
    pub fn as_int(&self) -> i32 {
        *self as i32
    }
}

/// Walk the SLSA Provenance v1 predicate looking for the builder id.
/// Returns L0 when the predicate isn't recognisable.
///
/// The conservative rule for slice 1:
/// - predicate_type does not start with `https://slsa.dev/provenance/` → L0
/// - missing `runDetails.builder.id` → L1 (statement exists, builder unknown)
/// - builder id present but issuer not in trusted list → L2
/// - builder id present AND issuer in trusted list → L3
pub fn infer_slsa_level(
    predicate_type: &str,
    predicate: &serde_json::Value,
    trusted_builders: &[&str],
) -> (SlsaLevel, Option<String>) {
    if !predicate_type.starts_with("https://slsa.dev/provenance/") {
        return (SlsaLevel::L0, None);
    }

    let builder_id = predicate
        .pointer("/runDetails/builder/id")
        .and_then(|v| v.as_str())
        .or_else(|| predicate.pointer("/builder/id").and_then(|v| v.as_str()))
        .map(|s| s.to_string());

    match builder_id {
        None => (SlsaLevel::L1, None),
        Some(id) => {
            let trusted = trusted_builders.iter().any(|b| id.starts_with(b));
            if trusted {
                (SlsaLevel::L3, Some(id))
            } else {
                (SlsaLevel::L2, Some(id))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_predicate_is_l0() {
        let (lvl, _) = infer_slsa_level("https://example/sbom", &serde_json::json!({}), &[]);
        assert_eq!(lvl, SlsaLevel::L0);
    }

    #[test]
    fn no_builder_is_l1() {
        let (lvl, _) = infer_slsa_level(
            "https://slsa.dev/provenance/v1",
            &serde_json::json!({}),
            &[],
        );
        assert_eq!(lvl, SlsaLevel::L1);
    }

    #[test]
    fn untrusted_builder_is_l2() {
        let pred = serde_json::json!({
            "runDetails": { "builder": { "id": "https://example.com/builder" } }
        });
        let (lvl, id) = infer_slsa_level("https://slsa.dev/provenance/v1", &pred, &[]);
        assert_eq!(lvl, SlsaLevel::L2);
        assert_eq!(id.as_deref(), Some("https://example.com/builder"));
    }

    #[test]
    fn trusted_builder_is_l3() {
        let pred = serde_json::json!({
            "runDetails": { "builder": { "id": "https://github.com/actions/runner" } }
        });
        let (lvl, _) = infer_slsa_level(
            "https://slsa.dev/provenance/v1",
            &pred,
            &["https://github.com/actions/"],
        );
        assert_eq!(lvl, SlsaLevel::L3);
    }
}
