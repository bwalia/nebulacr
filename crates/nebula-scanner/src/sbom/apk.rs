//! Alpine apk installed-db parser.
//!
//! Format: single-letter keys, colon-separated, one per line. Packages are
//! separated by blank lines.
//!   P: package name
//!   V: version
//!   o: origin (ignored)
//!
//! Ref: https://wiki.alpinelinux.org/wiki/Apk_spec

use super::Package;

pub fn parse(layer_digest: &str, contents: &[u8], out: &mut Vec<Package>) {
    let text = match std::str::from_utf8(contents) {
        Ok(s) => s,
        Err(_) => return,
    };
    for paragraph in text.split("\n\n") {
        let mut name: Option<&str> = None;
        let mut version: Option<&str> = None;
        for line in paragraph.lines() {
            if let Some(v) = line.strip_prefix("P:") {
                name = Some(v.trim());
            } else if let Some(v) = line.strip_prefix("V:") {
                version = Some(v.trim());
            }
        }
        if let (Some(n), Some(v)) = (name, version) {
            out.push(Package {
                name: n.to_string(),
                version: v.to_string(),
                ecosystem: "apk".into(),
                purl: format!("pkg:apk/alpine/{}@{}", n, v),
                layer_digest: Some(layer_digest.to_string()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
C:Q1abc
P:musl
V:1.2.3-r4
A:x86_64

C:Q1def
P:busybox
V:1.35.0-r29
A:x86_64
";

    #[test]
    fn parses_apk_db() {
        let mut out = Vec::new();
        parse("sha256:alpinelayer", FIXTURE.as_bytes(), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "musl");
        assert_eq!(out[0].version, "1.2.3-r4");
        assert_eq!(out[0].ecosystem, "apk");
        assert_eq!(out[0].purl, "pkg:apk/alpine/musl@1.2.3-r4");
        assert_eq!(out[1].name, "busybox");
    }
}
