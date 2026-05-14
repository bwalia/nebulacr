//! Lazy-pull indexer trait.
//!
//! Slice-1 deliverable: trait + format enum + error type. Concrete
//! implementations are slice 2-3.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndexFormat {
    Estargz,
    ZstdChunked,
    Soci,
}

impl IndexFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Estargz => "estargz",
            Self::ZstdChunked => "zstd-chunked",
            Self::Soci => "soci",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "estargz" => Some(Self::Estargz),
            "zstd-chunked" | "zstd_chunked" => Some(Self::ZstdChunked),
            "soci" => Some(Self::Soci),
            _ => None,
        }
    }

    /// OCI artifactType for the TOC referrer.
    pub fn artifact_type(&self) -> &'static str {
        match self {
            Self::Estargz => "application/vnd.containerd.stargz.toc.v1+json",
            Self::ZstdChunked => "application/vnd.containers.zstdchunked.toc.v1+json",
            Self::Soci => "application/vnd.amazon.soci.index.v1+json",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LazyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("layer not gzip/zstd compatible")]
    Unsupported,
    #[error("parser: {0}")]
    Parse(String),
    #[error("storage: {0}")]
    Storage(String),
}

/// Source of a layer's compressed bytes. Implementations stream so the
/// indexer never holds a full multi-GB layer in memory.
pub trait LayerSource: Send + Sync {
    fn digest(&self) -> &str;
    fn size_hint(&self) -> Option<u64>;
}

/// Pair of artifacts produced by indexing a single layer.
pub struct TocOutput {
    /// CycloneDX-shaped TOC blob, ready to be uploaded as an OCI
    /// artifact. The TOC's digest is computed by the caller after upload.
    pub toc_blob: Bytes,
    /// Optional rewritten layer (for eStargz / zstd:chunked). `None` for
    /// SOCI which does not rewrite the source layer.
    pub indexed_layer: Option<Bytes>,
    pub bytes_original: i64,
    pub bytes_indexed: i64,
}

#[async_trait]
pub trait TocIndexer: Send + Sync {
    fn format(&self) -> IndexFormat;

    /// Whether this indexer can produce a TOC for the given layer
    /// media type. The registry consults this before enqueueing.
    fn supports_media_type(&self, mt: &str) -> bool;

    /// Run the index pipeline. Implementations stream the input.
    async fn index(&self, src: Bytes) -> Result<TocOutput, LazyError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_round_trip() {
        for fmt in [
            IndexFormat::Estargz,
            IndexFormat::ZstdChunked,
            IndexFormat::Soci,
        ] {
            assert_eq!(IndexFormat::parse(fmt.as_str()), Some(fmt));
        }
    }

    #[test]
    fn artifact_type_per_format() {
        assert!(IndexFormat::Estargz.artifact_type().contains("stargz"));
        assert!(IndexFormat::Soci.artifact_type().contains("soci"));
    }
}
