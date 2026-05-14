//! Secret detector — walks gzipped tar layers and emits findings for
//! files containing credential-looking strings.
//!
//! Rule set is intentionally conservative: high-confidence regexes
//! only (AWS / GCP / Stripe / GitHub PAT / Slack token / generic SSH
//! private key block). Each rule has an explicit `allowed_paths` regex
//! so common test fixtures (`testdata/`, `**/test-fixtures/**`, etc.)
//! don't fire. False positives can be silenced via the existing
//! suppressions table.
//!
//! Slice scope: built-in rule corpus only. Operator-defined rule
//! files (gitleaks YAML import) is a follow-up.

use super::{Detector, DetectorError, Finding, FindingKind, FindingSeverity, FixSuggestion};
use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use regex::Regex;
use std::io::Read;
use std::sync::OnceLock;
use tar::Archive;

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FILES_PER_LAYER: usize = 5_000;

#[derive(Debug)]
struct Rule {
    id: &'static str,
    title: &'static str,
    severity: FindingSeverity,
    pattern: Regex,
    /// Paths the rule should NOT fire for, even if the pattern matches.
    allowed_paths: Regex,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        // Each pattern is a copy-pasted canonical string — picked to
        // minimise false positives.
        vec![
            Rule {
                id: "aws-access-key",
                title: "AWS access key id",
                severity: FindingSeverity::Critical,
                pattern: Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
                allowed_paths: Regex::new(r"(?i)(testdata|test-fixtures|fixtures/|examples?/)")
                    .unwrap(),
            },
            Rule {
                id: "gcp-service-account-key",
                title: "GCP service-account private key (JSON)",
                severity: FindingSeverity::Critical,
                pattern: Regex::new(r#""type"\s*:\s*"service_account""#).unwrap(),
                allowed_paths: Regex::new(r"(?i)(testdata|test-fixtures|fixtures/|examples?/)")
                    .unwrap(),
            },
            Rule {
                id: "github-pat",
                title: "GitHub personal access token",
                severity: FindingSeverity::Critical,
                pattern: Regex::new(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b").unwrap(),
                allowed_paths: Regex::new(r"(?i)(testdata|test-fixtures|fixtures/|examples?/)")
                    .unwrap(),
            },
            Rule {
                id: "stripe-secret-key",
                title: "Stripe secret key",
                severity: FindingSeverity::Critical,
                pattern: Regex::new(r"\bsk_(test|live)_[A-Za-z0-9]{24,}\b").unwrap(),
                allowed_paths: Regex::new(r"(?i)(testdata|test-fixtures|fixtures/|examples?/)")
                    .unwrap(),
            },
            Rule {
                id: "slack-bot-token",
                title: "Slack bot/user token",
                severity: FindingSeverity::High,
                pattern: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
                allowed_paths: Regex::new(r"(?i)(testdata|test-fixtures|fixtures/|examples?/)")
                    .unwrap(),
            },
            Rule {
                id: "ssh-private-key",
                title: "SSH / OpenSSL private key block",
                severity: FindingSeverity::High,
                pattern: Regex::new(
                    r"-----BEGIN (RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY( BLOCK)?-----",
                )
                .unwrap(),
                allowed_paths: Regex::new(
                    r"(?i)(testdata|test-fixtures|fixtures/|examples?/|/etc/ssh/)",
                )
                .unwrap(),
            },
            Rule {
                id: "jwt-token",
                title: "JWT token (header.payload.signature)",
                severity: FindingSeverity::Medium,
                pattern: Regex::new(
                    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
                )
                .unwrap(),
                allowed_paths: Regex::new(r"(?i)(testdata|test-fixtures|fixtures/|examples?/)")
                    .unwrap(),
            },
        ]
    })
}

pub struct SecretDetector;

impl SecretDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for SecretDetector {
    fn id(&self) -> FindingKind {
        FindingKind::Secret
    }

    fn supports_media_type(&self, mt: &str) -> bool {
        mt == "application/vnd.oci.image.layer.v1.tar+gzip"
            || mt == "application/vnd.docker.image.rootfs.diff.tar.gzip"
            || mt == "application/x-gzip"
    }

    async fn scan(&self, bytes: Bytes) -> Result<Vec<Finding>, DetectorError> {
        tokio::task::spawn_blocking(move || scan_layer(&bytes))
            .await
            .map_err(|e| DetectorError::Other(format!("secret tar walk panicked: {e}")))?
    }
}

fn scan_layer(bytes: &[u8]) -> Result<Vec<Finding>, DetectorError> {
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
                tracing::debug!(error = %e, "secret detector: skipping bad tar entry");
                continue;
            }
        };
        let header = entry.header().clone();
        // Only regular files. Skips devices, symlinks, dirs.
        if !header.entry_type().is_file() {
            continue;
        }
        let size = header.size().unwrap_or(0);
        if size == 0 || size > MAX_FILE_BYTES {
            continue;
        }
        let path = match entry.path() {
            Ok(p) => p.to_path_buf(),
            Err(_) => continue,
        };
        let path_str = path.to_string_lossy().to_string();

        // Skip obviously-binary file extensions to keep noise down.
        if is_binary_ext(&path_str) {
            continue;
        }

        let mut buf = Vec::with_capacity(size as usize);
        if entry.read_to_end(&mut buf).is_err() {
            continue;
        }
        files_examined += 1;
        let body = match std::str::from_utf8(&buf) {
            Ok(s) => s,
            Err(_) => continue, // not text — skip
        };

        for rule in rules() {
            if rule.allowed_paths.is_match(&path_str) {
                continue;
            }
            for m in rule.pattern.find_iter(body) {
                let line = body[..m.start()].matches('\n').count() as u32 + 1;
                findings.push(Finding {
                    kind: FindingKind::Secret,
                    severity: rule.severity,
                    finding_id: rule.id.to_string(),
                    title: rule.title.to_string(),
                    package: None,
                    path: Some(path_str.clone()),
                    line: Some(line),
                    fix: Some(FixSuggestion {
                        kind: "rotate-secret".into(),
                        detail: format!(
                            "Remove the secret from {} and rotate it at the issuing provider. \
                             Use a build-arg + secret store rather than embedding credentials \
                             in image layers.",
                            path_str
                        ),
                    }),
                });
                // One finding per (rule, file) is enough — additional
                // matches in the same file rarely add operator value.
                break;
            }
        }
    }

    Ok(findings)
}

fn is_binary_ext(path: &str) -> bool {
    const BINARY_EXTS: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".zip", ".gz", ".bz2",
        ".xz", ".tar", ".7z", ".br", ".zst", ".so", ".dylib", ".dll", ".a", ".o", ".class", ".jar",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".webm", ".mov", ".wav", ".ogg",
        ".pyc", ".pyo", ".wasm",
    ];
    let lower = path.to_ascii_lowercase();
    BINARY_EXTS.iter().any(|ext| lower.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder, Header};

    fn make_layer(files: &[(&str, &[u8])]) -> Bytes {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = Builder::new(&mut gz);
            for (name, body) in files {
                let mut h = Header::new_gnu();
                h.set_path(name).unwrap();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                tar.append(&h, *body).unwrap();
            }
            tar.finish().unwrap();
        }
        Bytes::from(gz.finish().unwrap())
    }

    #[tokio::test]
    async fn detects_aws_access_key() {
        let body = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let layer = make_layer(&[("etc/leak.env", body)]);
        let findings = SecretDetector::new().scan(layer).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_id, "aws-access-key");
        assert_eq!(findings[0].severity, FindingSeverity::Critical);
    }

    #[tokio::test]
    async fn allowlist_skips_test_fixtures() {
        let body = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let layer = make_layer(&[("repo/testdata/leak.env", body)]);
        let findings = SecretDetector::new().scan(layer).await.unwrap();
        assert_eq!(findings.len(), 0, "allowlist should skip testdata");
    }

    #[tokio::test]
    async fn detects_github_pat() {
        let body = b"token = ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let layer = make_layer(&[("config.toml", body)]);
        let findings = SecretDetector::new().scan(layer).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_id, "github-pat");
    }

    #[tokio::test]
    async fn detects_ssh_private_key() {
        let body =
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nblob\n-----END OPENSSH PRIVATE KEY-----\n";
        let layer = make_layer(&[("home/user/.ssh/id_rsa", body)]);
        let findings = SecretDetector::new().scan(layer).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_id, "ssh-private-key");
    }

    #[tokio::test]
    async fn skips_binary_extensions() {
        let body = b"AKIAIOSFODNN7EXAMPLE";
        let layer = make_layer(&[("a.png", body)]);
        let findings = SecretDetector::new().scan(layer).await.unwrap();
        assert_eq!(findings.len(), 0);
    }

    #[tokio::test]
    async fn one_finding_per_rule_per_file() {
        let body = b"k1=AKIAIOSFODNN7EXAMPLE\nk2=AKIAIOSFODNN7XAMPLES";
        let layer = make_layer(&[("multi.env", body)]);
        let findings = SecretDetector::new().scan(layer).await.unwrap();
        assert_eq!(findings.len(), 1, "dedup'd to one per file");
    }

    #[test]
    fn binary_ext_detection() {
        assert!(is_binary_ext("foo.png"));
        assert!(is_binary_ext("path/to/lib.SO"));
        assert!(!is_binary_ext("config.toml"));
        assert!(!is_binary_ext("readme.md"));
    }
}
