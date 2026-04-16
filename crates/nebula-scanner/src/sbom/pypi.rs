//! PyPI parser.
//!
//! Two input shapes:
//! 1. `*/*.dist-info/METADATA` — single installed distribution; emits one
//!    package with the Name/Version headers from the file.
//! 2. `requirements.txt` — one pinned spec per line. We only extract exact
//!    pins (`pkg==ver`) because fuzzy specs can't be matched against a CVE
//!    database without resolution.

use super::Package;

pub fn parse(layer_digest: &str, path: &str, contents: &[u8], out: &mut Vec<Package>) {
    if path.ends_with(".dist-info/METADATA") || path.ends_with(".egg-info/PKG-INFO") {
        parse_metadata(layer_digest, contents, out);
    } else if path.ends_with("requirements.txt") {
        parse_requirements(layer_digest, contents, out);
    }
}

fn parse_metadata(layer_digest: &str, contents: &[u8], out: &mut Vec<Package>) {
    let Ok(text) = std::str::from_utf8(contents) else {
        return;
    };
    let mut name: Option<&str> = None;
    let mut version: Option<&str> = None;
    // METADATA headers end at the first blank line.
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(v) = line.strip_prefix("Name: ") {
            name = Some(v.trim());
        } else if let Some(v) = line.strip_prefix("Version: ") {
            version = Some(v.trim());
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }
    if let (Some(n), Some(v)) = (name, version) {
        let norm = normalize_pypi(n);
        out.push(Package {
            name: norm.clone(),
            version: v.to_string(),
            ecosystem: "pypi".into(),
            purl: format!("pkg:pypi/{}@{}", norm, v),
            layer_digest: Some(layer_digest.to_string()),
        });
    }
}

fn parse_requirements(layer_digest: &str, contents: &[u8], out: &mut Vec<Package>) {
    let Ok(text) = std::str::from_utf8(contents) else {
        return;
    };
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue; // skip -r, -e, directives etc.
        }
        // Accept exact pins only; fuzzy specs (>=, ~=, *) aren't matchable.
        let Some((name, version)) = line.split_once("==") else {
            continue;
        };
        let version = version.split(';').next().unwrap_or(version).trim();
        let version = version.split('[').next().unwrap_or(version).trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        let norm = normalize_pypi(name.trim());
        out.push(Package {
            name: norm.clone(),
            version: version.to_string(),
            ecosystem: "pypi".into(),
            purl: format!("pkg:pypi/{}@{}", norm, version),
            layer_digest: Some(layer_digest.to_string()),
        });
    }
}

/// PEP 503 name normalisation: lowercase + runs of `_`/`.`/`-` → single `-`.
fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for c in name.chars() {
        let c = c.to_ascii_lowercase();
        if c == '_' || c == '.' || c == '-' {
            if !last_dash {
                out.push('-');
                last_dash = true;
            }
        } else {
            out.push(c);
            last_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_file() {
        let m = b"Metadata-Version: 2.1\nName: Django\nVersion: 4.2.0\nSummary: ...\n\nBody\n";
        let mut out = Vec::new();
        parse(
            "sha256:l",
            "usr/lib/python3.11/site-packages/Django-4.2.0.dist-info/METADATA",
            m,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "django");
        assert_eq!(out[0].version, "4.2.0");
        assert_eq!(out[0].purl, "pkg:pypi/django@4.2.0");
    }

    #[test]
    fn requirements_extracts_pins_only() {
        let r = b"# comment\nFlask==2.2.3\nrequests>=2.28  # fuzzy\njinja2==3.1.2 ; python_version>='3.7'\n";
        let mut out = Vec::new();
        parse("sha256:l", "app/requirements.txt", r, &mut out);
        let names: Vec<&str> = out.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"flask"));
        assert!(names.contains(&"jinja2"));
        assert!(!names.contains(&"requests"));
    }

    #[test]
    fn normalize_pep503() {
        assert_eq!(normalize_pypi("Python_Dateutil"), "python-dateutil");
        assert_eq!(normalize_pypi("MyLib..2"), "mylib-2");
    }
}
