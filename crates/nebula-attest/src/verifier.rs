//! DSSE signature verification.
//!
//! DSSE pre-authenticated encoding: `PAE("DSSEv1", payload_type,
//! payload_bytes)` is signed; verifiers reconstruct the same byte
//! string and check signatures against trusted public keys.
//!
//! Slice scope:
//! - Ed25519Verifier (ed25519-dalek)
//! - RsaVerifier (RSA PKCS#1 v1.5 SHA-256)
//!
//! Cosign keyless / Fulcio chain verification depends on 001 image
//! signing landing first; this is the manual-key path (cosign sign
//! --key, traditional keyserver flows). Both paths satisfy the same
//! `Verifier` trait so a future Fulcio impl plugs in here.

use crate::dsse::DsseEnvelope;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("no key matched any signature")]
    NoTrustedKey,
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("ed25519: {0}")]
    Ed25519(String),
    #[error("rsa: {0}")]
    Rsa(String),
    #[error("pem: {0}")]
    Pem(String),
    #[error("config: {0}")]
    Config(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifyVerdict {
    Verified,
    Unverified,
}

pub trait Verifier: Send + Sync {
    /// `keyid` is the DSSE signature's `keyid` field. Returning false
    /// means "this verifier doesn't own that key id"; the caller
    /// tries the next verifier. Returning true means "this verifier
    /// vouches for the key id."
    fn matches_keyid(&self, keyid: &str) -> bool;

    /// Verify a single DSSE signature. `pae` is the
    /// PAE("DSSEv1", payload_type, payload_bytes) preimage; `sig` is
    /// the raw signature bytes (already base64-decoded).
    fn verify_signature(&self, pae: &[u8], sig: &[u8]) -> Result<(), VerifyError>;
}

/// Build the DSSE pre-authenticated encoding the signer would have
/// signed: `PAE("DSSEv1", payload_type, payload_bytes)`.
///
/// Spec: <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>
pub fn dsse_pae(payload_type: &str, payload_bytes: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();
    let prefix = "DSSEv1";
    pae.extend_from_slice(format!("{} ", prefix.len()).as_bytes());
    pae.extend_from_slice(prefix.as_bytes());
    pae.extend_from_slice(format!(" {} ", payload_type.len()).as_bytes());
    pae.extend_from_slice(payload_type.as_bytes());
    pae.extend_from_slice(format!(" {} ", payload_bytes.len()).as_bytes());
    pae.extend_from_slice(payload_bytes);
    pae
}

/// Try every verifier against every signature in the envelope. The
/// first (verifier, signature) pair that verifies wins; if none
/// match, returns Unverified.
pub fn verify_envelope(
    env: &DsseEnvelope,
    verifiers: &[Box<dyn Verifier>],
) -> Result<VerifyVerdict, VerifyError> {
    let payload = base64::engine::general_purpose::STANDARD.decode(env.payload.as_bytes())?;
    let pae = dsse_pae(&env.payload_type, &payload);

    for sig_obj in &env.signatures {
        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig_obj.sig.as_bytes())?;
        for v in verifiers {
            if !v.matches_keyid(&sig_obj.keyid) {
                continue;
            }
            if v.verify_signature(&pae, &sig_bytes).is_ok() {
                return Ok(VerifyVerdict::Verified);
            }
        }
    }
    Ok(VerifyVerdict::Unverified)
}

// ── Ed25519 verifier ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Ed25519Verifier {
    pub keyid: String,
    pub public: ed25519_dalek::VerifyingKey,
}

impl Ed25519Verifier {
    /// Construct from a 32-byte public key.
    pub fn from_bytes(keyid: impl Into<String>, key: &[u8]) -> Result<Self, VerifyError> {
        let arr: [u8; 32] = key.try_into().map_err(|_| {
            VerifyError::Config(format!("ed25519 key must be 32 bytes, got {}", key.len()))
        })?;
        let public = ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| VerifyError::Ed25519(e.to_string()))?;
        Ok(Self {
            keyid: keyid.into(),
            public,
        })
    }
}

impl Verifier for Ed25519Verifier {
    fn matches_keyid(&self, keyid: &str) -> bool {
        // Empty keyid in the DSSE envelope means "try every verifier"
        // — common with cosign which doesn't set keyid.
        keyid.is_empty() || keyid == self.keyid
    }
    fn verify_signature(&self, pae: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
        let arr: [u8; 64] = sig.try_into().map_err(|_| {
            VerifyError::Ed25519(format!("ed25519 sig must be 64 bytes, got {}", sig.len()))
        })?;
        let signature = ed25519_dalek::Signature::from_bytes(&arr);
        use ed25519_dalek::Verifier as _;
        self.public
            .verify(pae, &signature)
            .map_err(|e| VerifyError::Ed25519(e.to_string()))
    }
}

// ── RSA verifier (PKCS#1 v1.5 SHA-256) ───────────────────────────────────────

pub struct RsaVerifier {
    pub keyid: String,
    pub public: rsa::RsaPublicKey,
}

impl RsaVerifier {
    pub fn new(keyid: impl Into<String>, public: rsa::RsaPublicKey) -> Self {
        Self {
            keyid: keyid.into(),
            public,
        }
    }
}

impl Verifier for RsaVerifier {
    fn matches_keyid(&self, keyid: &str) -> bool {
        keyid.is_empty() || keyid == self.keyid
    }
    fn verify_signature(&self, pae: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier as _;
        let v: VerifyingKey<sha2::Sha256> = VerifyingKey::new(self.public.clone());
        let signature = Signature::try_from(sig).map_err(|e| VerifyError::Rsa(e.to_string()))?;
        v.verify(pae, &signature)
            .map_err(|e| VerifyError::Rsa(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsse::DsseSignature;

    #[test]
    fn pae_round_trip_matches_spec() {
        // DSSE spec example: PAE("DSSEv1", "x", "y") =
        // "6 DSSEv1 1 x 1 y"
        let pae = dsse_pae("x", b"y");
        assert_eq!(pae, b"6 DSSEv1 1 x 1 y");
    }

    #[test]
    fn ed25519_round_trip_verifies() {
        // Generate a fresh ed25519 keypair, sign a known PAE, verify.
        use ed25519_dalek::{Signer, SigningKey};
        let mut rng_bytes = [42u8; 32];
        // Simple deterministic-ish "rng" for tests.
        for (i, b) in rng_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        let signing = SigningKey::from_bytes(&rng_bytes);
        let public = signing.verifying_key();
        let payload = b"{\"_type\":\"https://in-toto.io/Statement/v1\"}";
        let pae = dsse_pae("application/vnd.in-toto+json", payload);
        let sig = signing.sign(&pae);

        let env = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".into(),
            payload: base64::engine::general_purpose::STANDARD.encode(payload),
            signatures: vec![DsseSignature {
                keyid: "k1".into(),
                sig: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            }],
        };
        let verifier = Ed25519Verifier::from_bytes("k1", public.as_bytes()).unwrap();
        let verdict = verify_envelope(&env, &[Box::new(verifier) as Box<dyn Verifier>]).unwrap();
        assert_eq!(verdict, VerifyVerdict::Verified);
    }

    #[test]
    fn ed25519_wrong_key_returns_unverified() {
        use ed25519_dalek::{Signer, SigningKey};
        let signer_a = SigningKey::from_bytes(&[1u8; 32]);
        let signer_b_pub = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        let payload = b"abc";
        let pae = dsse_pae("text/plain", payload);
        let sig = signer_a.sign(&pae);

        let env = DsseEnvelope {
            payload_type: "text/plain".into(),
            payload: base64::engine::general_purpose::STANDARD.encode(payload),
            signatures: vec![DsseSignature {
                keyid: "".into(),
                sig: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            }],
        };
        let v = Ed25519Verifier::from_bytes("any", signer_b_pub.as_bytes()).unwrap();
        let verdict = verify_envelope(&env, &[Box::new(v) as Box<dyn Verifier>]).unwrap();
        assert_eq!(verdict, VerifyVerdict::Unverified);
    }

    #[test]
    fn ed25519_keyid_filter_skips_other_keys() {
        use ed25519_dalek::{Signer, SigningKey};
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let public = signer.verifying_key();
        let payload = b"x";
        let pae = dsse_pae("text/plain", payload);
        let sig = signer.sign(&pae);

        let env = DsseEnvelope {
            payload_type: "text/plain".into(),
            payload: base64::engine::general_purpose::STANDARD.encode(payload),
            signatures: vec![DsseSignature {
                // Explicit keyid the verifier doesn't own.
                keyid: "rotated-key".into(),
                sig: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            }],
        };
        let v = Ed25519Verifier::from_bytes("primary-key", public.as_bytes()).unwrap();
        let verdict = verify_envelope(&env, &[Box::new(v) as Box<dyn Verifier>]).unwrap();
        assert_eq!(verdict, VerifyVerdict::Unverified);
    }

    #[test]
    fn rejects_malformed_ed25519_key_size() {
        let err = Ed25519Verifier::from_bytes("k", &[0u8; 16]).unwrap_err();
        matches!(err, VerifyError::Config(_));
    }
}
