//! npm package-lock parser.
//!
//! Supports lockfile v2/v3 (`packages` object keyed by install path). Falls
//! back to v1 (`dependencies` tree) when `packages` is absent. Workspace
//! root entries are skipped (empty key or entries without a version).

use serde::Deserialize;

use super::Package;

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    packages: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    dependencies: Option<serde_json::Map<String, serde_json::Value>>,
}

pub fn parse(layer_digest: &str, contents: &[u8], out: &mut Vec<Package>) {
    let Ok(lock): Result<Lock, _> = serde_json::from_slice(contents) else {
        return;
    };

    if let Some(packages) = lock.packages {
        for (key, entry) in packages {
            if key.is_empty() {
                continue; // workspace root
            }
            let Some(name) = name_from_key(&key) else {
                continue;
            };
            let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            out.push(Package {
                name: name.to_string(),
                version: version.to_string(),
                ecosystem: "npm".into(),
                purl: npm_purl(name, version),
                layer_digest: Some(layer_digest.to_string()),
            });
        }
        return;
    }

    if let Some(deps) = lock.dependencies {
        walk_v1(&deps, layer_digest, out);
    }
}

fn walk_v1(
    deps: &serde_json::Map<String, serde_json::Value>,
    layer_digest: &str,
    out: &mut Vec<Package>,
) {
    for (name, entry) in deps {
        if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
            out.push(Package {
                name: name.clone(),
                version: version.to_string(),
                ecosystem: "npm".into(),
                purl: npm_purl(name, version),
                layer_digest: Some(layer_digest.to_string()),
            });
        }
        if let Some(children) = entry.get("dependencies").and_then(|v| v.as_object()) {
            walk_v1(children, layer_digest, out);
        }
    }
}

/// Extract the package name from a v2/v3 `packages` key like
/// `"node_modules/@scope/pkg"` or `"node_modules/pkg/node_modules/inner"`.
fn name_from_key(key: &str) -> Option<&str> {
    let after = key.rsplit("node_modules/").next()?;
    if after.is_empty() { None } else { Some(after) }
}

fn npm_purl(name: &str, version: &str) -> String {
    if let Some(rest) = name.strip_prefix('@')
        && let Some((scope, pkg)) = rest.split_once('/')
    {
        return format!("pkg:npm/%40{}/{}@{}", scope, pkg, version);
    }
    format!("pkg:npm/{}@{}", name, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V3: &str = r#"{
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/express": {"version": "4.17.1"},
        "node_modules/@babel/core": {"version": "7.22.0"}
      }
    }"#;

    #[test]
    fn parses_v3_lockfile() {
        let mut out = Vec::new();
        parse("sha256:l", V3.as_bytes(), &mut out);
        let names: Vec<&str> = out.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"@babel/core"));
        let babel = out.iter().find(|p| p.name == "@babel/core").unwrap();
        assert_eq!(babel.purl, "pkg:npm/%40babel/core@7.22.0");
    }

    const V1: &str = r#"{
      "lockfileVersion": 1,
      "dependencies": {
        "lodash": {"version": "4.17.21"},
        "chalk": {
          "version": "4.1.2",
          "dependencies": {
            "ansi-styles": {"version": "4.3.0"}
          }
        }
      }
    }"#;

    #[test]
    fn parses_v1_lockfile() {
        let mut out = Vec::new();
        parse("sha256:l", V1.as_bytes(), &mut out);
        let names: Vec<&str> = out.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"chalk"));
        assert!(names.contains(&"ansi-styles"));
    }
}
