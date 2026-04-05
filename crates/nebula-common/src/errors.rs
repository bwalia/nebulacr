use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("blob unknown: {digest}")]
    BlobUnknown { digest: String },

    #[error("blob upload invalid")]
    BlobUploadInvalid,

    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestInvalid { expected: String, actual: String },

    #[error("manifest unknown: {reference}")]
    ManifestUnknown { reference: String },

    #[error("manifest invalid: {reason}")]
    ManifestInvalid { reason: String },

    #[error("repository not found: {name}")]
    NameUnknown { name: String },

    #[error("tag unknown: {tag}")]
    TagUnknown { tag: String },

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {reason}")]
    Forbidden { reason: String },

    #[error("tenant not found: {tenant}")]
    TenantNotFound { tenant: String },

    #[error("project not found: {project}")]
    ProjectNotFound { project: String },

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    #[error("token expired")]
    TokenExpired,

    #[error("token invalid: {reason}")]
    TokenInvalid { reason: String },

    #[error("internal error: {0}")]
    Internal(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("circuit breaker open for {target}")]
    CircuitBreakerOpen { target: String },

    #[error("upstream registry error: {0}")]
    UpstreamError(String),

    #[error("all retries exhausted: {0}")]
    RetriesExhausted(String),

    #[error("region failover: {0}")]
    FailoverError(String),
}

/// OCI error response envelope.
#[derive(Serialize)]
struct OciErrorResponse {
    errors: Vec<OciError>,
}

#[derive(Serialize)]
struct OciError {
    code: &'static str,
    message: String,
    detail: Option<String>,
}

impl RegistryError {
    fn oci_code(&self) -> &'static str {
        match self {
            Self::BlobUnknown { .. } => "BLOB_UNKNOWN",
            Self::BlobUploadInvalid => "BLOB_UPLOAD_INVALID",
            Self::DigestInvalid { .. } => "DIGEST_INVALID",
            Self::ManifestUnknown { .. } => "MANIFEST_UNKNOWN",
            Self::ManifestInvalid { .. } => "MANIFEST_INVALID",
            Self::NameUnknown { .. } => "NAME_UNKNOWN",
            Self::TagUnknown { .. } => "TAG_UNKNOWN",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden { .. } => "DENIED",
            Self::TenantNotFound { .. } => "NAME_UNKNOWN",
            Self::ProjectNotFound { .. } => "NAME_UNKNOWN",
            Self::RateLimitExceeded => "TOOMANYREQUESTS",
            Self::TokenExpired | Self::TokenInvalid { .. } => "UNAUTHORIZED",
            Self::Internal(_) | Self::Storage(_) => "UNKNOWN",
            Self::CircuitBreakerOpen { .. } => "UNAVAILABLE",
            Self::UpstreamError(_) => "UPSTREAM_ERROR",
            Self::RetriesExhausted(_) => "RETRIES_EXHAUSTED",
            Self::FailoverError(_) => "FAILOVER_ERROR",
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::BlobUnknown { .. }
            | Self::ManifestUnknown { .. }
            | Self::NameUnknown { .. }
            | Self::TagUnknown { .. }
            | Self::TenantNotFound { .. }
            | Self::ProjectNotFound { .. } => StatusCode::NOT_FOUND,
            Self::BlobUploadInvalid | Self::DigestInvalid { .. } | Self::ManifestInvalid { .. } => {
                StatusCode::BAD_REQUEST
            }
            Self::Unauthorized | Self::TokenExpired | Self::TokenInvalid { .. } => {
                StatusCode::UNAUTHORIZED
            }
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) | Self::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::CircuitBreakerOpen { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamError(_) | Self::RetriesExhausted(_) => StatusCode::BAD_GATEWAY,
            Self::FailoverError(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = OciErrorResponse {
            errors: vec![OciError {
                code: self.oci_code(),
                message: self.to_string(),
                detail: None,
            }],
        };
        let mut response = (status, axum::Json(body)).into_response();
        // Docker Registry V2 spec requires Www-Authenticate on 401 responses
        if status == StatusCode::UNAUTHORIZED {
            let realm =
                std::env::var("NEBULACR_AUTH_REALM").unwrap_or_else(|_| "/auth/token".to_string());
            let service = std::env::var("NEBULACR_AUTH_SERVICE")
                .unwrap_or_else(|_| "nebulacr-registry".to_string());
            let header_val = format!("Bearer realm=\"{realm}\",service=\"{service}\"");
            if let Ok(val) = axum::http::HeaderValue::from_str(&header_val) {
                response.headers_mut().insert("Www-Authenticate", val);
            }
        }
        response
    }
}
