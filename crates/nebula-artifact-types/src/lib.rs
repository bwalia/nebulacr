//! NebulaCR typed artifact validators.
//!
//! Slice 1 ships the ArtifactType trait, the validator registry, the
//! Helm chart validator, and the schema. WASM / model / Terraform
//! validators land in slices 2-3.

pub mod helm;
pub mod model;
pub mod registry;
pub mod store;
pub mod tfmodule;
pub mod types;
pub mod wasm;

pub use helm::HelmType;
pub use model::ModelType;
pub use registry::ArtifactRegistry;
pub use store::{ArtifactMetaRow, ArtifactStore, PgArtifactStore};
pub use tfmodule::TerraformModuleType;
pub use types::{ArtifactError, ArtifactMetadata, ArtifactType, ArtifactTypeId};
pub use wasm::WasmType;
