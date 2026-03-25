use sha2::{Digest, Sha256};

/// Compute the sha256 digest of a byte slice, returning `sha256:<hex>`.
pub fn sha256_digest(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("sha256:{}", hex::encode(hash))
}

/// Build the object-store path for a blob.
/// Layout: `<tenant>/<project>/<repo>/blobs/sha256/<hex>`
pub fn blob_path(tenant: &str, project: &str, repo: &str, digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("{tenant}/{project}/{repo}/blobs/sha256/{hex}")
}

/// Build the object-store path for a manifest by tag or digest.
/// Layout: `<tenant>/<project>/<repo>/manifests/<reference>`
pub fn manifest_path(tenant: &str, project: &str, repo: &str, reference: &str) -> String {
    format!("{tenant}/{project}/{repo}/manifests/{reference}")
}

/// Build the path to the tag→digest link.
/// Layout: `<tenant>/<project>/<repo>/tags/<tag>`
pub fn tag_link_path(tenant: &str, project: &str, repo: &str, tag: &str) -> String {
    format!("{tenant}/{project}/{repo}/tags/{tag}")
}

/// Build the path prefix for listing tags.
pub fn tags_prefix(tenant: &str, project: &str, repo: &str) -> String {
    format!("{tenant}/{project}/{repo}/tags/")
}

/// Build the upload session path.
pub fn upload_path(tenant: &str, project: &str, repo: &str, upload_id: &str) -> String {
    format!("{tenant}/{project}/{repo}/uploads/{upload_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_digest() {
        let d = sha256_digest(b"hello");
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_blob_path() {
        let p = blob_path("acme", "web", "nginx", "sha256:abc123");
        assert_eq!(p, "acme/web/nginx/blobs/sha256/abc123");
    }
}
