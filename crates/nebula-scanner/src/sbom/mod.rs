//! SBOM extraction from layer filesystems.
//!
//! Each parser keys off a filesystem path pattern observed during
//! `image::Puller::walk_layers`. Parsers are pure — given bytes at a path,
//! emit zero or more `Package` records. Final aggregation is an SBOM-like
//! list which the matcher consumes.
//!
//! Individual parsers filled in task #6.

use serde::{Deserialize, Serialize};

pub mod apk;
pub mod cargo;
pub mod dpkg;
pub mod go;
pub mod npm;
pub mod pypi;
pub mod rpm;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: String, // deb | rpm | apk | npm | cargo | pypi | go | maven
    pub purl: String,
    pub layer_digest: Option<String>,
}

/// Dispatch a path+bytes pair to the appropriate parser, appending any
/// packages found to `out`. Unknown paths are silently ignored.
pub fn dispatch(layer_digest: &str, path: &str, contents: &[u8], out: &mut Vec<Package>) {
    // dpkg status file (Debian/Ubuntu).
    if path == "var/lib/dpkg/status" || path.ends_with("/dpkg/status") {
        dpkg::parse(layer_digest, contents, out);
        return;
    }
    // Alpine apk installed database.
    if path == "lib/apk/db/installed" || path.ends_with("/apk/db/installed") {
        apk::parse(layer_digest, contents, out);
        return;
    }
    // RPM Berkeley DB or sqlite.
    if path.ends_with("var/lib/rpm/Packages") || path.ends_with("var/lib/rpm/rpmdb.sqlite") {
        rpm::parse(layer_digest, contents, out);
        return;
    }
    // Language manifests.
    if path.ends_with("package-lock.json") || path.ends_with("npm-shrinkwrap.json") {
        npm::parse(layer_digest, contents, out);
        return;
    }
    if path.ends_with("Cargo.lock") {
        cargo::parse(layer_digest, contents, out);
        return;
    }
    if path.ends_with("requirements.txt") || path.ends_with(".dist-info/METADATA") {
        pypi::parse(layer_digest, path, contents, out);
        return;
    }
    if path.ends_with("go.sum") {
        go::parse(layer_digest, contents, out);
    }
}
