//! In-process mesh used for unit tests and the cfg-disabled-mesh path.
//!
//! Real deployments use the libp2p impl (later slice). This impl runs
//! entirely in one process, useful for testing the registry's
//! integration with `PeerMesh` without spinning up multiple nodes.

use crate::mesh::{MeshError, PeerEndpoint, PeerMesh};
use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct LocalMesh {
    /// (digest -> blob bytes) — the local cache.
    blobs: Arc<RwLock<HashMap<String, Bytes>>>,
    /// Other LocalMesh instances acting as "peers". Used in tests.
    peers: Arc<RwLock<Vec<LocalMesh>>>,
    /// This instance's identity.
    pub endpoint: PeerEndpoint,
}

impl LocalMesh {
    pub fn new(libp2p_id: impl Into<String>, addr: impl Into<String>) -> Self {
        Self {
            blobs: Default::default(),
            peers: Default::default(),
            endpoint: PeerEndpoint {
                libp2p_id: libp2p_id.into(),
                addr: addr.into(),
            },
        }
    }

    pub fn add_peer(&self, other: LocalMesh) {
        self.peers.write().unwrap().push(other);
    }

    pub fn put_blob(&self, digest: impl Into<String>, bytes: Bytes) {
        self.blobs.write().unwrap().insert(digest.into(), bytes);
    }
}

#[async_trait]
impl PeerMesh for LocalMesh {
    async fn announce(&self, _digests: &[String]) -> Result<(), MeshError> {
        Ok(())
    }

    async fn lookup(&self, digest: &str) -> Result<Vec<PeerEndpoint>, MeshError> {
        let mut found = Vec::new();
        for peer in self.peers.read().unwrap().iter() {
            if peer.blobs.read().unwrap().contains_key(digest) {
                found.push(peer.endpoint.clone());
            }
        }
        Ok(found)
    }

    async fn fetch_from(&self, peer: &PeerEndpoint, digest: &str) -> Result<Bytes, MeshError> {
        for p in self.peers.read().unwrap().iter() {
            if p.endpoint == *peer {
                let bytes = p
                    .blobs
                    .read()
                    .unwrap()
                    .get(digest)
                    .cloned()
                    .ok_or_else(|| MeshError::Unavailable(digest.into()))?;

                // Content-addressability check: the returned bytes MUST
                // hash to the digest we asked for.
                let expected_hex = digest.strip_prefix("sha256:").unwrap_or(digest);
                let got = format!("{:x}", Sha256::digest(&bytes));
                if got != expected_hex {
                    return Err(MeshError::DigestMismatch {
                        expected: expected_hex.into(),
                        got,
                    });
                }
                return Ok(bytes);
            }
        }
        Err(MeshError::Unavailable(peer.libp2p_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lookup_finds_peer_with_blob() {
        let me = LocalMesh::new("me", "127.0.0.1:1");
        let other = LocalMesh::new("other", "127.0.0.1:2");
        let bytes = Bytes::from_static(b"hello");
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        other.put_blob(&digest, bytes);
        me.add_peer(other);

        let peers = me.lookup(&digest).await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].libp2p_id, "other");
    }

    #[tokio::test]
    async fn fetch_verifies_content_address() {
        let me = LocalMesh::new("me", "127.0.0.1:1");
        let peer = LocalMesh::new("peer", "127.0.0.1:2");
        peer.put_blob(
            "sha256:dead0000000000000000000000000000000000000000000000000000000000ad",
            Bytes::from_static(b"poisoned"),
        );
        me.add_peer(peer.clone());

        let res = me
            .fetch_from(
                &peer.endpoint,
                "sha256:dead0000000000000000000000000000000000000000000000000000000000ad",
            )
            .await;
        match res {
            Err(MeshError::DigestMismatch { .. }) => {}
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_returns_blob_when_digest_matches() {
        let me = LocalMesh::new("me", "127.0.0.1:1");
        let peer = LocalMesh::new("peer", "127.0.0.1:2");
        let bytes = Bytes::from_static(b"hello");
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        peer.put_blob(&digest, bytes.clone());
        me.add_peer(peer.clone());

        let got = me.fetch_from(&peer.endpoint, &digest).await.unwrap();
        assert_eq!(got, bytes);
    }
}
