//! NebulaCR attestation store + verifier.
//!
//! Slice 1 ships the DSSE envelope parser, the SLSA-level extractor,
//! the AttestationStore trait + Postgres impl, and the schema.
//! Verification (signature checks via nebula-signing, builder
//! allowlist, material match) lands in slice 2; admission integration
//! in slice 3.

pub mod dsse;
pub mod slsa;
pub mod store;
pub mod verifier;

pub use dsse::{DsseEnvelope, DsseError, decode_envelope};
pub use slsa::{SlsaLevel, infer_slsa_level};
pub use store::{Attestation, AttestationStore, PgAttestationStore};
pub use verifier::{
    Ed25519Verifier, RsaVerifier, Verifier, VerifyError, VerifyVerdict, dsse_pae, verify_envelope,
};
