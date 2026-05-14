//! NebulaCR migration importer.
//!
//! Slice-1 deliverable: RegistrySource trait + DistributionSource
//! (vanilla OCI Distribution v2 — the simplest adapter), the
//! ImportJob model, and the persistence schema. Nexus / Harbor / ACR
//! adapters and the runner ship in later slices.

pub mod acr;
pub mod destination;
pub mod distribution;
pub mod harbor;
pub mod jobs;
pub mod nexus;
pub mod runner;
pub mod source;

pub use acr::AcrSource;
pub use destination::{InMemoryDestination, RegistryDestination};
pub use distribution::DistributionSource;
pub use harbor::HarborSource;
pub use jobs::{ImportJobRow, ImportJobStore, ImportPhase, PgImportJobStore};
pub use nexus::NexusSource;
pub use runner::{ImportRunReport, ImportRunner, ImportRunnerConfig};
pub use source::{ImportError, RegistrySource, Repository, Tag};
