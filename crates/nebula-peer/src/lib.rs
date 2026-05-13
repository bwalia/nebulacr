//! NebulaCR peer mesh — P2P pull acceleration.
//!
//! Slice-1 deliverable: PeerMesh trait + an in-process LocalMesh used
//! for tests + the registry-side membership store. The libp2p
//! transport and the DaemonSet binary ship in later slices.

pub mod local;
pub mod mesh;
pub mod registry_store;

pub use local::LocalMesh;
pub use mesh::{PeerEndpoint, PeerMesh, MeshError};
pub use registry_store::{MeshRow, NodeRow, PeerMeshStore, PgPeerMeshStore};
