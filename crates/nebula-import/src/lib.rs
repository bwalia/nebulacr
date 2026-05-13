//! NebulaCR migration importer.
//!
//! Slice-1 deliverable: RegistrySource trait + DistributionSource
//! (vanilla OCI Distribution v2 — the simplest adapter), the
//! ImportJob model, and the persistence schema. Nexus / Harbor / ACR
//! adapters and the runner ship in later slices.

pub mod distribution;
pub mod jobs;
pub mod source;

pub use distribution::DistributionSource;
pub use jobs::{ImportJobRow, ImportJobStore, ImportPhase, PgImportJobStore};
pub use source::{ImportError, Repository, RegistrySource, Tag};
