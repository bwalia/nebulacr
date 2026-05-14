//! Minimal DSSE (Dead Simple Signing Envelope) parser.
//!
//! https://github.com/secure-systems-lab/dsse
//!
//! Slice 1: parse the envelope shape and extract the inner in-toto
//! statement. Signature verification is slice 2 (delegated to
//! `nebula-signing` once 001 lands).

use base64::Engine as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String, // base64 of the in-toto statement
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    #[serde(default)]
    pub keyid: String,
    pub sig: String, // base64 sig
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub stmt_type: String,
    pub subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoSubject {
    #[serde(default)]
    pub name: String,
    pub digest: std::collections::HashMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DsseError {
    #[error("invalid envelope JSON: {0}")]
    EnvelopeJson(serde_json::Error),
    #[error("payload base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid statement JSON: {0}")]
    StatementJson(serde_json::Error),
}

/// Decode a DSSE bundle into the envelope + parsed in-toto statement.
pub fn decode_envelope(bytes: &[u8]) -> Result<(DsseEnvelope, InTotoStatement), DsseError> {
    let env: DsseEnvelope = serde_json::from_slice(bytes).map_err(DsseError::EnvelopeJson)?;
    let payload = base64::engine::general_purpose::STANDARD.decode(env.payload.as_bytes())?;
    let stmt: InTotoStatement =
        serde_json::from_slice(&payload).map_err(DsseError::StatementJson)?;
    Ok((env, stmt))
}

/// Convenience: pull the canonical sha256 digest of the first subject.
pub fn first_subject_digest(stmt: &InTotoStatement) -> Option<String> {
    stmt.subject.first().and_then(|s| {
        s.digest
            .get("sha256")
            .map(|h| format!("sha256:{}", h.trim_start_matches("sha256:")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_envelope(predicate_type: &str, subject_sha256: &str) -> Vec<u8> {
        let stmt = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": "image",
                "digest": { "sha256": subject_sha256 }
            }],
            "predicateType": predicate_type,
            "predicate": {}
        });
        let payload =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&stmt).unwrap());
        let env = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload,
            "signatures": [{ "keyid": "k1", "sig": "AAAA" }]
        });
        serde_json::to_vec(&env).unwrap()
    }

    #[test]
    fn decodes_valid_envelope() {
        let raw = make_envelope("https://slsa.dev/provenance/v1", "deadbeef");
        let (env, stmt) = decode_envelope(&raw).unwrap();
        assert_eq!(env.signatures.len(), 1);
        assert_eq!(stmt.predicate_type, "https://slsa.dev/provenance/v1");
        assert_eq!(
            first_subject_digest(&stmt).as_deref(),
            Some("sha256:deadbeef")
        );
    }

    #[test]
    fn rejects_garbage() {
        let err = decode_envelope(b"not json").unwrap_err();
        matches!(err, DsseError::EnvelopeJson(_));
    }
}
