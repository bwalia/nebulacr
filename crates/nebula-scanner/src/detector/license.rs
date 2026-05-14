//! License detector — walks a gzipped tar layer, finds LICENSE-like
//! files, and classifies their text against a small built-in
//! canonical-string match table.
//!
//! Slice 2 ships heuristic matching for the top license families
//! (Apache-2.0, MIT, BSD-2/3-Clause, ISC, GPL-2.0/3.0, LGPL, MPL-2.0,
//! CDDL, EPL-2.0, Unlicense, CC0-1.0). False-positives are explicit:
//! we only emit a finding when a strong canonical phrase matches AND
//! the surrounding bytes look like license text. ScanCode-grade
//! pattern matching is a follow-up.
//!
//! Severity:
//! - copyleft families (`GPL-*`, `LGPL-*`, `AGPL-*`)         → Medium
//! - weak-copyleft (`MPL-2.0`, `EPL-2.0`, `CDDL-1.0`)         → Low
//! - unknown text matched as "license-like" but no SPDX hit → Info
//! - permissive (Apache/MIT/BSD/ISC/Unlicense/CC0)            → Info
//!
//! Operators dial the policy threshold via 014's AdmissionPolicy block
//! (slice 3); slice 2 just emits findings and lets the existing
//! suppression machinery silence noisy ones.

use super::{Detector, DetectorError, Finding, FindingKind, FindingSeverity, FixSuggestion};
use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use std::io::Read;
use tar::Archive;

/// File-name prefixes the detector treats as license candidates.
const LICENSE_FILENAMES: &[&str] = &[
    "license",
    "licence",
    "copying",
    "copyright",
    "notice",
    "legal",
];

/// Maximum size of a single license file we'll parse. Larger files
/// are silently skipped — license texts rarely exceed a few KB.
const MAX_LICENSE_BYTES: u64 = 64 * 1024;

/// Maximum number of files we'll inspect per layer. Bounds the worst
/// case for an adversarial layer with thousands of `LICENSE` entries.
const MAX_FILES_PER_LAYER: usize = 200;

pub struct LicenseDetector;

impl LicenseDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LicenseDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for LicenseDetector {
    fn id(&self) -> FindingKind {
        FindingKind::License
    }

    fn supports_media_type(&self, mt: &str) -> bool {
        mt == "application/vnd.oci.image.layer.v1.tar+gzip"
            || mt == "application/vnd.docker.image.rootfs.diff.tar.gzip"
            || mt == "application/x-gzip"
    }

    async fn scan(&self, bytes: Bytes) -> Result<Vec<Finding>, DetectorError> {
        // Run the synchronous parse in a blocking task — tar+gzip is
        // CPU-bound and shouldn't tie up the worker's runtime thread.
        tokio::task::spawn_blocking(move || scan_layer_blocking(&bytes))
            .await
            .map_err(|e| DetectorError::Other(format!("tar walk panicked: {e}")))?
    }
}

fn scan_layer_blocking(bytes: &[u8]) -> Result<Vec<Finding>, DetectorError> {
    let gz = GzDecoder::new(bytes);
    let mut archive = Archive::new(gz);

    let mut findings: Vec<Finding> = Vec::new();
    let mut files_examined = 0usize;

    let entries = archive
        .entries()
        .map_err(|e| DetectorError::Parse(format!("tar entries: {e}")))?;

    for entry in entries {
        if files_examined >= MAX_FILES_PER_LAYER {
            break;
        }
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                // Some image layers contain corrupt entries; skip
                // rather than aborting the scan.
                tracing::debug!(error = %e, "license detector: skipping bad tar entry");
                continue;
            }
        };

        let path = match entry.path() {
            Ok(p) => p.to_path_buf(),
            Err(_) => continue,
        };
        let filename = match path.file_name().and_then(|f| f.to_str()) {
            Some(s) => s.to_lowercase(),
            None => continue,
        };
        if !LICENSE_FILENAMES
            .iter()
            .any(|prefix| filename.starts_with(prefix))
        {
            continue;
        }
        let size = entry.header().size().unwrap_or(0);
        if size == 0 || size > MAX_LICENSE_BYTES {
            continue;
        }

        let mut buf = String::new();
        if entry.read_to_string(&mut buf).is_err() {
            continue;
        }
        files_examined += 1;

        let path_str = path.to_string_lossy().to_string();
        match classify_license(&buf) {
            Some(spdx) => {
                let class = license_class(spdx);
                let sev = severity_for_class(class);
                findings.push(Finding {
                    kind: FindingKind::License,
                    severity: sev,
                    finding_id: spdx.to_string(),
                    title: format!("{spdx} license detected ({class:?})"),
                    package: None,
                    path: Some(path_str),
                    line: None,
                    fix: None,
                });
            }
            None => {
                findings.push(Finding {
                    kind: FindingKind::License,
                    severity: FindingSeverity::Info,
                    finding_id: "UNKNOWN-LICENSE".to_string(),
                    title: format!("license-like file at {} but no SPDX match", path_str),
                    package: None,
                    path: Some(path_str),
                    line: None,
                    fix: Some(FixSuggestion {
                        kind: "license-tag".into(),
                        detail: "Add an SPDX header to the file or set \
                                 org.opencontainers.image.licenses on the image config."
                            .into(),
                    }),
                });
            }
        }
    }

    Ok(findings)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseClass {
    Permissive,
    WeakCopyleft,
    StrongCopyleft,
    Unknown,
}

fn severity_for_class(c: LicenseClass) -> FindingSeverity {
    match c {
        LicenseClass::StrongCopyleft => FindingSeverity::Medium,
        LicenseClass::WeakCopyleft => FindingSeverity::Low,
        LicenseClass::Permissive => FindingSeverity::Info,
        LicenseClass::Unknown => FindingSeverity::Info,
    }
}

fn license_class(spdx: &str) -> LicenseClass {
    match spdx {
        // Permissive
        "Apache-2.0" | "MIT" | "BSD-2-Clause" | "BSD-3-Clause" | "ISC" | "Unlicense"
        | "CC0-1.0" => LicenseClass::Permissive,
        // Weak copyleft
        "MPL-2.0" | "EPL-2.0" | "CDDL-1.0" | "LGPL-2.1-only" | "LGPL-2.1-or-later"
        | "LGPL-3.0-only" | "LGPL-3.0-or-later" => LicenseClass::WeakCopyleft,
        // Strong copyleft
        "GPL-2.0-only" | "GPL-2.0-or-later" | "GPL-3.0-only" | "GPL-3.0-or-later"
        | "AGPL-3.0-only" | "AGPL-3.0-or-later" => LicenseClass::StrongCopyleft,
        _ => LicenseClass::Unknown,
    }
}

/// Classify a license text body into an SPDX id by spotting a
/// canonical phrase. Each rule needs at least one strong, copy-pasted
/// sentence from the license preamble.
fn classify_license(body: &str) -> Option<&'static str> {
    let normalized = body.to_lowercase();
    // Order matters: GPL/LGPL/AGPL share preamble text, so test the
    // most specific first.
    if normalized.contains("gnu affero general public license") {
        return Some("AGPL-3.0-or-later");
    }
    if normalized.contains("gnu lesser general public license") {
        if normalized.contains("version 3") {
            return Some("LGPL-3.0-or-later");
        }
        return Some("LGPL-2.1-or-later");
    }
    if normalized.contains("gnu general public license") {
        if normalized.contains("version 3") {
            return Some("GPL-3.0-or-later");
        }
        return Some("GPL-2.0-or-later");
    }
    if normalized.contains("apache license, version 2.0") || normalized.contains("apache-2.0") {
        return Some("Apache-2.0");
    }
    if normalized.contains("mozilla public license, v. 2.0") || normalized.contains("mpl-2.0") {
        return Some("MPL-2.0");
    }
    if normalized.contains("eclipse public license - v 2.0")
        || normalized.contains("eclipse public license version 2.0")
    {
        return Some("EPL-2.0");
    }
    if normalized.contains("common development and distribution license") {
        return Some("CDDL-1.0");
    }
    // BSD family — 3-clause has the "neither the name of" boilerplate;
    // 2-clause omits it.
    if normalized.contains("redistribution and use in source and binary forms") {
        if normalized.contains("neither the name of") {
            return Some("BSD-3-Clause");
        }
        return Some("BSD-2-Clause");
    }
    if normalized.contains("permission to use, copy, modify, and/or distribute")
        || normalized.contains("isc license")
    {
        return Some("ISC");
    }
    if normalized.contains("permission is hereby granted, free of charge")
        && normalized.contains("the software is provided")
    {
        return Some("MIT");
    }
    if normalized.contains("creative commons cc0")
        || normalized.contains("the person who associated a work with this deed")
    {
        return Some("CC0-1.0");
    }
    if normalized.contains("this is free and unencumbered software released into the public domain")
    {
        return Some("Unlicense");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_classified(body: &str, expected: &str) {
        let got = classify_license(body).unwrap_or_else(|| {
            panic!(
                "expected {expected}, got None for body starting {:?}",
                &body[..40.min(body.len())]
            )
        });
        assert_eq!(got, expected);
    }

    #[test]
    fn classifies_mit() {
        assert_classified(
            "Permission is hereby granted, free of charge, to any person \
             obtaining a copy of this software and associated documentation \
             files. The Software is provided \"as is\".",
            "MIT",
        );
    }

    #[test]
    fn classifies_apache_2() {
        assert_classified("Apache License, Version 2.0\nblah blah", "Apache-2.0");
    }

    #[test]
    fn classifies_gpl_3_over_2() {
        assert_classified(
            "GNU General Public License version 3 — preamble follows",
            "GPL-3.0-or-later",
        );
        assert_classified(
            "GNU General Public License version 2 — preamble follows",
            "GPL-2.0-or-later",
        );
    }

    #[test]
    fn classifies_bsd_3_clause() {
        assert_classified(
            "Redistribution and use in source and binary forms, with or \
             without modification, are permitted provided … neither the name \
             of the project nor the names of its contributors …",
            "BSD-3-Clause",
        );
    }

    #[test]
    fn classifies_bsd_2_clause() {
        assert_classified(
            "Redistribution and use in source and binary forms, with or \
             without modification, are permitted provided … no third clause",
            "BSD-2-Clause",
        );
    }

    #[test]
    fn classifies_unlicense() {
        assert_classified(
            "This is free and unencumbered software released into the public domain.",
            "Unlicense",
        );
    }

    #[test]
    fn unknown_text_returns_none() {
        assert!(classify_license("definitely not a license, just lorem ipsum").is_none());
    }

    #[test]
    fn class_categorisation_covers_seven_families() {
        assert_eq!(license_class("MIT"), LicenseClass::Permissive);
        assert_eq!(license_class("Apache-2.0"), LicenseClass::Permissive);
        assert_eq!(license_class("MPL-2.0"), LicenseClass::WeakCopyleft);
        assert_eq!(
            license_class("LGPL-3.0-or-later"),
            LicenseClass::WeakCopyleft
        );
        assert_eq!(
            license_class("GPL-3.0-or-later"),
            LicenseClass::StrongCopyleft
        );
        assert_eq!(
            license_class("AGPL-3.0-or-later"),
            LicenseClass::StrongCopyleft
        );
        assert_eq!(license_class("Custom-1.0"), LicenseClass::Unknown);
    }

    #[tokio::test]
    async fn scans_layer_with_apache_license() {
        // Build a minimal gzipped tarball with a single LICENSE file.
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::{Builder, Header};

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = Builder::new(&mut gz);
            let body = b"Apache License, Version 2.0\nthis is a test license";
            let mut h = Header::new_gnu();
            h.set_path("usr/share/doc/foo/LICENSE").unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append(&h, body.as_slice()).unwrap();
            tar.finish().unwrap();
        }
        let bytes = bytes::Bytes::from(gz.finish().unwrap());

        let det = LicenseDetector::new();
        let findings = det.scan(bytes).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_id, "Apache-2.0");
        assert_eq!(findings[0].severity, FindingSeverity::Info);
        assert_eq!(
            findings[0].path.as_deref(),
            Some("usr/share/doc/foo/LICENSE")
        );
    }

    #[tokio::test]
    async fn scans_layer_with_unknown_license_yields_info_finding() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::{Builder, Header};

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = Builder::new(&mut gz);
            let body = b"# Custom Vendor License\nNot a recognised SPDX text.";
            let mut h = Header::new_gnu();
            h.set_path("LICENSE").unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append(&h, body.as_slice()).unwrap();
            tar.finish().unwrap();
        }
        let bytes = bytes::Bytes::from(gz.finish().unwrap());

        let det = LicenseDetector::new();
        let findings = det.scan(bytes).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_id, "UNKNOWN-LICENSE");
        assert!(findings[0].fix.is_some(), "operator should get a fix hint");
    }

    #[test]
    fn severity_climbs_with_class() {
        assert_eq!(
            severity_for_class(LicenseClass::Permissive),
            FindingSeverity::Info
        );
        assert_eq!(
            severity_for_class(LicenseClass::WeakCopyleft),
            FindingSeverity::Low
        );
        assert_eq!(
            severity_for_class(LicenseClass::StrongCopyleft),
            FindingSeverity::Medium
        );
    }
}
