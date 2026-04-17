//! GitHub fix-commit / patch-diff crawler.
//!
//! Vulnerability advisories (especially from GHSA and OSV) frequently
//! include references pointing at the commit that landed the fix. We
//! extract GitHub commit URLs from the references list, fetch each
//! commit via the GitHub API, and return the patch diff. Downstream
//! use: richer context for the AI CVE analyser (it can reason about the
//! actual patch instead of inferring from the summary).

use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// A parsed GitHub commit reference.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CommitRef {
    pub owner: String,
    pub repo: String,
    pub sha: String,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct FixCommit {
    pub commit: CommitRef,
    pub message: String,
    pub author: Option<String>,
    pub files_changed: usize,
    pub patch: String,
}

#[derive(Debug, Deserialize)]
struct GhCommit {
    sha: String,
    commit: GhCommitInner,
    #[serde(default)]
    files: Vec<GhFile>,
}

#[derive(Debug, Deserialize)]
struct GhCommitInner {
    message: String,
    author: Option<GhAuthor>,
}

#[derive(Debug, Deserialize)]
struct GhAuthor {
    name: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhFile {
    filename: String,
    #[serde(default)]
    patch: Option<String>,
}

pub fn extract_commit_refs(references: &[String]) -> Vec<CommitRef> {
    let re = Regex::new(r"https://github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]{7,40})")
        .expect("static regex");
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in references {
        if let Some(caps) = re.captures(r) {
            let sha = caps[3].to_string();
            let owner = caps[1].to_string();
            let repo = caps[2].to_string();
            let key = format!("{owner}/{repo}/{sha}");
            if seen.insert(key) {
                out.push(CommitRef {
                    owner,
                    repo,
                    sha,
                    url: r.clone(),
                });
            }
        }
    }
    out
}

/// Fetch a single commit's patch from GitHub. Token is optional (anonymous
/// calls rate-limit at 60/hr); the GitHub Enterprise base URL is overridable.
pub async fn fetch_commit(
    token: Option<&str>,
    base_url: Option<&str>,
    c: &CommitRef,
) -> Result<FixCommit, String> {
    let base = base_url.unwrap_or("https://api.github.com");
    let url = format!(
        "{base}/repos/{owner}/{repo}/commits/{sha}",
        base = base.trim_end_matches('/'),
        owner = c.owner,
        repo = c.repo,
        sha = c.sha
    );
    let client = Client::new();
    let mut req = client
        .get(&url)
        .header("User-Agent", "nebulacr-scanner")
        .header("Accept", "application/vnd.github+json");
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("github request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("github {status}: {body}"));
    }
    let gc: GhCommit = resp
        .json()
        .await
        .map_err(|e| format!("github commit decode: {e}"))?;

    let patch: String = gc
        .files
        .iter()
        .filter_map(|f| {
            f.patch
                .as_ref()
                .map(|p| format!("--- a/{}\n+++ b/{}\n{p}\n", f.filename, f.filename))
        })
        .collect::<Vec<_>>()
        .join("\n");

    let author = gc
        .commit
        .author
        .and_then(|a| a.name.or(a.email));

    Ok(FixCommit {
        commit: CommitRef {
            owner: c.owner.clone(),
            repo: c.repo.clone(),
            sha: gc.sha,
            url: c.url.clone(),
        },
        message: gc.commit.message,
        author,
        files_changed: gc.files.len(),
        patch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_commit_urls_from_references() {
        let refs = vec![
            "https://github.com/rust-lang/rust/commit/abc1234".into(),
            "https://github.com/example/app/commit/a1b2c3d4e5f6789012345678901234567890abcd"
                .into(),
            "https://example.com/commits/abc".into(),
        ];
        let commits = extract_commit_refs(&refs);
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].owner, "rust-lang");
        assert_eq!(commits[0].repo, "rust");
        assert_eq!(commits[0].sha, "abc1234");
        assert_eq!(commits[1].sha.len(), 40);
    }

    #[test]
    fn dedupes_same_commit_in_multiple_references() {
        let refs = vec![
            "https://github.com/a/b/commit/deadbeef".into(),
            "https://github.com/a/b/commit/deadbeef#diff".into(),
        ];
        let commits = extract_commit_refs(&refs);
        assert_eq!(commits.len(), 1);
    }

    #[test]
    fn ignores_non_commit_urls() {
        let refs = vec![
            "https://github.com/a/b/pull/123".into(),
            "https://github.com/a/b/issues/456".into(),
        ];
        assert!(extract_commit_refs(&refs).is_empty());
    }
}
