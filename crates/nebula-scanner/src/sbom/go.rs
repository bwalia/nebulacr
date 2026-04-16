//! Go module parser — `go.sum` lockfile.
//!
//! Each dependency appears on up to two lines in `go.sum`:
//!   `<module> <version> h1:<hash>=`
//!   `<module> <version>/go.mod h1:<hash>=`
//! We dedup on `(module, version)` and treat the two forms as equivalent.

use std::collections::HashSet;

use super::Package;

pub fn parse(layer_digest: &str, contents: &[u8], out: &mut Vec<Package>) {
    let Ok(text) = std::str::from_utf8(contents) else {
        return;
    };
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(module), Some(version_raw), Some(_hash)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let version = version_raw.strip_suffix("/go.mod").unwrap_or(version_raw);
        if !version.starts_with('v') {
            continue;
        }
        let key = (module.to_string(), version.to_string());
        if !seen.insert(key) {
            continue;
        }
        out.push(Package {
            name: module.to_string(),
            version: version.to_string(),
            ecosystem: "go".into(),
            purl: format!("pkg:golang/{}@{}", module, version),
            layer_digest: Some(layer_digest.to_string()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
golang.org/x/net v0.17.0 h1:ghi=
golang.org/x/net v0.17.0/go.mod h1:jkl=
github.com/pkg/errors v0.9.1/go.mod h1:mno=
";

    #[test]
    fn parses_go_sum_and_dedups_go_mod_lines() {
        let mut out = Vec::new();
        parse("sha256:gol", FIXTURE.as_bytes(), &mut out);
        assert_eq!(out.len(), 3);
        let names: Vec<&str> = out.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"github.com/gin-gonic/gin"));
        assert!(names.contains(&"golang.org/x/net"));
        assert!(names.contains(&"github.com/pkg/errors"));
        let gin = out
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin.version, "v1.9.1");
        assert_eq!(gin.ecosystem, "go");
        assert_eq!(gin.purl, "pkg:golang/github.com/gin-gonic/gin@v1.9.1");
        assert_eq!(gin.layer_digest.as_deref(), Some("sha256:gol"));
    }

    #[test]
    fn ignores_malformed_lines() {
        let src = "\
github.com/foo/bar
not a valid line
github.com/ok/ok v1.0.0 h1:aaa=
";
        let mut out = Vec::new();
        parse("sha256:l", src.as_bytes(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "github.com/ok/ok");
    }

    #[test]
    fn ignores_non_v_prefixed_versions() {
        // Defensive: real go.sum versions always start with 'v'.
        let src = "github.com/x/y 1.0.0 h1:zz=\n";
        let mut out = Vec::new();
        parse("sha256:l", src.as_bytes(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn handles_pseudo_versions_and_incompatible() {
        let src = "\
github.com/foo/bar v0.0.0-20231010123456-abcdef123456 h1:aa=
github.com/foo/bar v0.0.0-20231010123456-abcdef123456/go.mod h1:bb=
github.com/old/lib v2.3.4+incompatible h1:cc=
";
        let mut out = Vec::new();
        parse("sha256:l", src.as_bytes(), &mut out);
        assert_eq!(out.len(), 2);
        let pseudo = out.iter().find(|p| p.name == "github.com/foo/bar").unwrap();
        assert_eq!(pseudo.version, "v0.0.0-20231010123456-abcdef123456");
        let incompat = out.iter().find(|p| p.name == "github.com/old/lib").unwrap();
        assert_eq!(incompat.version, "v2.3.4+incompatible");
    }
}
