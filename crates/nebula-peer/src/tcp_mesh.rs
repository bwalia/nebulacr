//! TCP-based gossip mesh (slice-2 transport).
//!
//! A pure-tokio TCP transport that satisfies the `PeerMesh` trait
//! without adding rust-libp2p's transitive dep load. Each node:
//!
//! - listens on a TCP port for inbound JSON-line requests
//!   (`announce` / `lookup` / `fetch`)
//! - keeps a list of peer addresses (configured at construction; in
//!   slice 3 a real DHT replaces this)
//! - announces digests it holds to every peer on a heartbeat
//! - responds to `lookup(digest)` with its own libp2p_id when it
//!   holds the blob, otherwise empty
//! - serves blob bytes on `fetch(digest)` with sha256 verification
//!
//! The libp2p impl is a follow-up; this transport already gives
//! single-cluster operators something usable. Kept entirely behind
//! the `PeerMesh` trait so the swap is transparent.

use crate::mesh::{MeshError, PeerEndpoint, PeerMesh};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const MAX_BLOB_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB hard cap
const FETCH_LINE_BUF: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    Lookup {
        digest: String,
    },
    Fetch {
        digest: String,
    },
    Announce {
        libp2p_id: String,
        digests: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Response {
    Ok,
    Lookup {
        has: bool,
    },
    /// `len` bytes follow on the same TCP stream after the JSON line.
    Fetch {
        len: u64,
    },
    Error {
        message: String,
    },
}

/// A node's view of the mesh. Holds the local cache, the configured
/// peer list, and the listener join-handle.
pub struct GossipTcpMesh {
    pub endpoint: PeerEndpoint,
    blobs: Arc<RwLock<HashMap<String, Bytes>>>,
    peers: Arc<RwLock<Vec<PeerEndpoint>>>,
}

impl GossipTcpMesh {
    /// Construct the mesh and start the listener on `bind_addr`.
    pub async fn bind(
        libp2p_id: impl Into<String>,
        bind_addr: SocketAddr,
        bootstrap_peers: Vec<PeerEndpoint>,
    ) -> Result<Self, MeshError> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| MeshError::Transport(format!("bind {bind_addr}: {e}")))?;
        let endpoint = PeerEndpoint {
            libp2p_id: libp2p_id.into(),
            addr: bind_addr.to_string(),
        };
        let blobs: Arc<RwLock<HashMap<String, Bytes>>> = Default::default();
        let mesh = Self {
            endpoint: endpoint.clone(),
            blobs: blobs.clone(),
            peers: Arc::new(RwLock::new(bootstrap_peers)),
        };
        // Spawn the inbound handler.
        let blobs_listener = blobs.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((sock, _)) => {
                        let blobs = blobs_listener.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_inbound(sock, blobs).await {
                                tracing::debug!(error = %e, "peer mesh: inbound failed");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "peer mesh: accept failed");
                    }
                }
            }
        });
        Ok(mesh)
    }

    /// Add a blob to the local cache.
    pub fn put_blob(&self, digest: impl Into<String>, bytes: Bytes) {
        self.blobs.write().unwrap().insert(digest.into(), bytes);
    }

    /// Add a peer at runtime (e.g. after a discovery event).
    pub fn add_peer(&self, peer: PeerEndpoint) {
        self.peers.write().unwrap().push(peer);
    }
}

async fn handle_inbound(
    mut sock: TcpStream,
    blobs: Arc<RwLock<HashMap<String, Bytes>>>,
) -> Result<(), std::io::Error> {
    let (read, mut write) = sock.split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let err = Response::Error {
                message: format!("bad request: {e}"),
            };
            write_json_line(&mut write, &err).await?;
            return Ok(());
        }
    };

    match req {
        Request::Lookup { digest } => {
            let has = blobs.read().unwrap().contains_key(&digest);
            write_json_line(&mut write, &Response::Lookup { has }).await?;
        }
        Request::Fetch { digest } => {
            let blob = blobs.read().unwrap().get(&digest).cloned();
            match blob {
                Some(bytes) => {
                    write_json_line(
                        &mut write,
                        &Response::Fetch {
                            len: bytes.len() as u64,
                        },
                    )
                    .await?;
                    write.write_all(&bytes).await?;
                }
                None => {
                    write_json_line(
                        &mut write,
                        &Response::Error {
                            message: "not found".into(),
                        },
                    )
                    .await?;
                }
            }
        }
        Request::Announce { .. } => {
            // Slice-2 transport just acknowledges — the bookkeeping
            // table is updated by the registry-side store. Slice-3
            // libp2p will do real DHT updates.
            write_json_line(&mut write, &Response::Ok).await?;
        }
    }
    Ok(())
}

async fn write_json_line<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    r: &Response,
) -> Result<(), std::io::Error> {
    let mut bytes = serde_json::to_vec(r).unwrap();
    bytes.push(b'\n');
    w.write_all(&bytes).await
}

async fn read_json_line<R: tokio::io::AsyncBufReadExt + Unpin>(
    r: &mut R,
) -> Result<Response, MeshError> {
    let mut line = String::new();
    r.read_line(&mut line)
        .await
        .map_err(|e| MeshError::Transport(format!("read: {e}")))?;
    serde_json::from_str(&line).map_err(|e| MeshError::Transport(format!("parse: {e}")))
}

#[async_trait]
impl PeerMesh for GossipTcpMesh {
    async fn announce(&self, digests: &[String]) -> Result<(), MeshError> {
        let peers: Vec<PeerEndpoint> = self.peers.read().unwrap().clone();
        let me_id = self.endpoint.libp2p_id.clone();
        for peer in peers {
            let req = Request::Announce {
                libp2p_id: me_id.clone(),
                digests: digests.to_vec(),
            };
            // Best-effort — failures don't surface to the caller.
            let _ = round_trip(&peer.addr, &req).await;
        }
        Ok(())
    }

    async fn lookup(&self, digest: &str) -> Result<Vec<PeerEndpoint>, MeshError> {
        let peers: Vec<PeerEndpoint> = self.peers.read().unwrap().clone();
        let mut found = Vec::new();
        for peer in peers {
            let resp = round_trip(
                &peer.addr,
                &Request::Lookup {
                    digest: digest.to_string(),
                },
            )
            .await;
            match resp {
                Ok(Response::Lookup { has: true }) => found.push(peer),
                _ => {}
            }
        }
        Ok(found)
    }

    async fn fetch_from(&self, peer: &PeerEndpoint, digest: &str) -> Result<Bytes, MeshError> {
        // Open one connection, send Fetch, parse Response::Fetch
        // header + drain `len` bytes.
        let stream = TcpStream::connect(&peer.addr)
            .await
            .map_err(|e| MeshError::Transport(format!("connect {}: {e}", peer.addr)))?;
        let (read, mut write) = tokio::io::split(stream);
        let mut reader = BufReader::with_capacity(FETCH_LINE_BUF, read);

        let req = Request::Fetch {
            digest: digest.to_string(),
        };
        let mut req_bytes = serde_json::to_vec(&req).unwrap();
        req_bytes.push(b'\n');
        write
            .write_all(&req_bytes)
            .await
            .map_err(|e| MeshError::Transport(format!("write: {e}")))?;

        let header = read_json_line(&mut reader).await?;
        let len = match header {
            Response::Fetch { len } => len,
            Response::Error { message } => return Err(MeshError::Unavailable(message)),
            other => return Err(MeshError::Transport(format!("unexpected: {other:?}"))),
        };
        if len > MAX_BLOB_BYTES {
            return Err(MeshError::Transport(format!("blob too large: {len}")));
        }
        let mut buf = vec![0u8; len as usize];
        reader
            .read_exact(&mut buf)
            .await
            .map_err(|e| MeshError::Transport(format!("read body: {e}")))?;

        // Content-addressability check — drop poisoned bytes.
        let expected_hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        let got = format!("{:x}", Sha256::digest(&buf));
        if got != expected_hex {
            return Err(MeshError::DigestMismatch {
                expected: expected_hex.into(),
                got,
            });
        }
        Ok(Bytes::from(buf))
    }
}

async fn round_trip(addr: &str, req: &Request) -> Result<Response, MeshError> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| MeshError::Transport(format!("connect {addr}: {e}")))?;
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut bytes = serde_json::to_vec(req).unwrap();
    bytes.push(b'\n');
    write
        .write_all(&bytes)
        .await
        .map_err(|e| MeshError::Transport(format!("write: {e}")))?;
    read_json_line(&mut reader).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pick an ephemeral port that's currently free. Repeated tests
    /// use distinct ports so the listener tasks don't collide.
    async fn ephemeral_port() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        addr
    }

    #[tokio::test]
    async fn lookup_round_trip() {
        let a_addr = ephemeral_port().await;
        let b_addr = ephemeral_port().await;
        let b_endpoint = PeerEndpoint {
            libp2p_id: "b".into(),
            addr: b_addr.to_string(),
        };
        let _b = GossipTcpMesh::bind("b", b_addr, vec![]).await.unwrap();
        let a = GossipTcpMesh::bind("a", a_addr, vec![b_endpoint.clone()])
            .await
            .unwrap();

        // No blob yet — lookup returns empty.
        let peers = a.lookup("sha256:deadbeef").await.unwrap();
        assert!(peers.is_empty());

        // Put a blob on b, lookup again — finds b.
        _b.put_blob("sha256:deadbeef", Bytes::from_static(b"x"));
        let peers = a.lookup("sha256:deadbeef").await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].libp2p_id, "b");
    }

    #[tokio::test]
    async fn fetch_returns_blob_when_digest_matches() {
        let body = b"hello world".to_vec();
        let digest = format!("sha256:{:x}", Sha256::digest(&body));
        let b_addr = ephemeral_port().await;
        let b = GossipTcpMesh::bind("b", b_addr, vec![]).await.unwrap();
        b.put_blob(digest.clone(), Bytes::from(body.clone()));

        let a_addr = ephemeral_port().await;
        let a = GossipTcpMesh::bind(
            "a",
            a_addr,
            vec![PeerEndpoint {
                libp2p_id: "b".into(),
                addr: b_addr.to_string(),
            }],
        )
        .await
        .unwrap();
        let got = a
            .fetch_from(
                &PeerEndpoint {
                    libp2p_id: "b".into(),
                    addr: b_addr.to_string(),
                },
                &digest,
            )
            .await
            .unwrap();
        assert_eq!(&got[..], &body[..]);
    }

    #[tokio::test]
    async fn fetch_rejects_poisoned_blob() {
        // Peer claims a digest but ships different bytes — receiver
        // must reject via DigestMismatch.
        let claimed_digest =
            "sha256:dead0000000000000000000000000000000000000000000000000000000000ad";
        let b_addr = ephemeral_port().await;
        let b = GossipTcpMesh::bind("b", b_addr, vec![]).await.unwrap();
        b.put_blob(claimed_digest, Bytes::from_static(b"poisoned-bytes"));

        let a_addr = ephemeral_port().await;
        let a = GossipTcpMesh::bind("a", a_addr, vec![]).await.unwrap();
        let res = a
            .fetch_from(
                &PeerEndpoint {
                    libp2p_id: "b".into(),
                    addr: b_addr.to_string(),
                },
                claimed_digest,
            )
            .await;
        match res {
            Err(MeshError::DigestMismatch { .. }) => {}
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }
}
