use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Tenant hierarchy ──────────────────────────────────────────────

/// Top-level organizational unit. Maps to a company or team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub storage_prefix: String,
    pub rate_limit_rps: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A project within a tenant. Owns repositories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub visibility: Visibility,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Repository within a project. Contains image manifests + blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub id: Uuid,
    pub project_id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Private,
    Public,
}

// ── OCI types ─────────────────────────────────────────────────────

/// An OCI image manifest (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema_version: u32,
    pub media_type: String,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

/// Tag listing response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagList {
    pub name: String,
    pub tags: Vec<String>,
}

/// Catalog listing response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    pub repositories: Vec<String>,
}

// ── RBAC ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Maintainer,
    Reader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pull,
    Push,
    Delete,
    Tag,
    Manage,
}

impl Role {
    /// Actions permitted for this role.
    pub fn allowed_actions(&self) -> &'static [Action] {
        match self {
            Role::Admin => &[
                Action::Pull,
                Action::Push,
                Action::Delete,
                Action::Tag,
                Action::Manage,
            ],
            Role::Maintainer => &[Action::Pull, Action::Push, Action::Delete, Action::Tag],
            Role::Reader => &[Action::Pull],
        }
    }

    pub fn can(&self, action: Action) -> bool {
        self.allowed_actions().contains(&action)
    }
}

/// Access policy binding a subject to a role within a scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub project_id: Option<Uuid>,
    pub subject: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}
