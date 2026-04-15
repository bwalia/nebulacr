//! Debian/Ubuntu dpkg status parser.
//!
//! Format: RFC-822-style paragraphs separated by blank lines. Each paragraph
//! describes one installed package. We read `Package:`, `Version:`, and
//! `Status:` — packages whose status does not contain "installed" are skipped
//! (e.g. "config-files" leftovers).

use super::Package;

pub fn parse(layer_digest: &str, contents: &[u8], out: &mut Vec<Package>) {
    let text = match std::str::from_utf8(contents) {
        Ok(s) => s,
        Err(_) => return,
    };
    for paragraph in text.split("\n\n") {
        let mut name: Option<&str> = None;
        let mut version: Option<&str> = None;
        let mut status_installed = false;
        for line in paragraph.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = Some(v.trim());
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = Some(v.trim());
            } else if let Some(v) = line.strip_prefix("Status: ") {
                status_installed = v.split_whitespace().any(|tok| tok == "installed");
            }
        }
        if let (Some(n), Some(v)) = (name, version) {
            if status_installed {
                out.push(Package {
                    name: n.to_string(),
                    version: v.to_string(),
                    ecosystem: "deb".into(),
                    purl: format!("pkg:deb/debian/{}@{}", n, v),
                    layer_digest: Some(layer_digest.to_string()),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
Package: openssl
Status: install ok installed
Version: 1.1.1k-1
Architecture: amd64

Package: libc6
Status: install ok installed
Version: 2.31-13+deb11u5
Architecture: amd64

Package: stale
Status: deinstall ok config-files
Version: 0.0.1
";

    #[test]
    fn parses_installed_only() {
        let mut out = Vec::new();
        parse("sha256:layer", FIXTURE.as_bytes(), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "openssl");
        assert_eq!(out[0].version, "1.1.1k-1");
        assert_eq!(out[0].ecosystem, "deb");
        assert_eq!(out[0].purl, "pkg:deb/debian/openssl@1.1.1k-1");
        assert_eq!(out[0].layer_digest.as_deref(), Some("sha256:layer"));
        assert_eq!(out[1].name, "libc6");
    }
}
