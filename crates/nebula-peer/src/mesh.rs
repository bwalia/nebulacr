//! Peer-mesh trait — swappable transport (libp2p in later slices).

use async_trait::async_trait;
use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub libp2p_id: String,
    pub addr: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("peer unavailable: {0}")]
    Unavailable(String),
    #[error("digest mismatch: expected {expected}, got {got}")]
    DigestMismatch { expected: String, got: String },
    #[error("transport: {0}")]
    Transport(String),
}

#[async_trait]
pub trait PeerMesh: Send + Sync {
    /// Announce blobs this peer holds.
    async fn announce(&self, digests: &[String]) -> Result<(), MeshError>;

    /// Find peers that claim to hold a given digest.
    async fn lookup(&self, digest: &str) -> Result<Vec<PeerEndpoint>, MeshError>;

    /// Stream a blob from a peer. Implementations MUST verify the
    /// returned bytes hash to the requested digest before returning;
    /// hash mismatch is `MeshError::DigestMismatch`.
    async fn fetch_from(&self, peer: &PeerEndpoint, digest: &str) -> Result<Bytes, MeshError>;
}
