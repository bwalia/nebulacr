//! NebulaCR lazy-pull indexer.
//!
//! Slice 1 ships the `TocIndexer` trait, the per-format media-type
//! constants, and the bookkeeping schema. Indexers themselves
//! (eStargz / zstd-chunked / SOCI) land in slices 2-3; the registry
//! does NOT enqueue any work yet.

pub mod indexer;
pub mod jobs;
pub mod referrers;

pub use indexer::{IndexFormat, TocIndexer, TocOutput, LayerSource, LazyError};
pub use jobs::{JobStatus, LazyJob, LazyJobStore, PgLazyJobStore};
pub use referrers::{Referrer, ReferrerStore, PgReferrerStore};
