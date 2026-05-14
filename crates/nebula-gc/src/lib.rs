//! NebulaCR online garbage collector.
//!
//! Slice 1 ships the live refcount writer:
//! - [`BlobRefCounter`] trait — `add_refs` on manifest push, `remove_refs`
//!   on manifest delete. Both run inside a caller-supplied Postgres tx so
//!   the refcount mutation is atomic with the manifest mutation.
//! - [`PgBlobRefCounter`] — the Postgres implementation backed by tables
//!   created by `migrations/0004_online_gc.sql`.
//! - [`extract_blob_digests`] — pulls layer + config descriptors out of an
//!   OCI manifest or image index without needing the registry to depend
//!   on this crate's parser.
//!
//! Slice 2 adds:
//! - [`ContinuousReaper`] — drains zero-refcount blobs older than the
//!   grace period, deletes their storage objects, removes the
//!   bookkeeping rows.
//! - [`ReaperControl`] — pause / resume / shutdown handles.
//! - `blob_paths` table (migration 0015) so the reaper knows every
//!   storage location for a digest.
//!
//! Slices 3-4 add the reconciler and operator surfaces (CLI / MCP / Helm).
//! They share these traits.

pub mod manifest;
pub mod reaper;
pub mod reconciler;
pub mod refcount;

pub use manifest::{extract_blob_digests, BlobDescriptor, ManifestParseError};
pub use reaper::{
    ContinuousReaper, CycleResult, ReaperConfig, ReaperControl, ReaperStats,
};
pub use reconciler::{ReconcileConfig, ReconcileStats, Reconciler};
pub use refcount::{BlobRefCounter, GcError, NoopBlobRefCounter, PgBlobRefCounter};
