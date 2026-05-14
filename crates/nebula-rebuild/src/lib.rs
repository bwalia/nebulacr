//! NebulaCR auto-rebuild on base CVE patch.
//!
//! Slice 1 ships the lineage extractor (label-based + history-based)
//! and the schema. The subscription reconciler + emitters
//! (GitHub/GitLab/Tekton/webhook) ship in slices 2-3.

pub mod emitter;
pub mod lineage;
pub mod rate_limit;

pub use emitter::{
    compute_webhook_signature, EmitError, GenericWebhookEmitter, GitHubDispatchEmitter,
    GitLabPipelineEmitter, RebuildEmitter, RebuildEvent, TektonEventListenerEmitter,
    TriggerCause,
};
pub use lineage::{detect_lineage, LineageConfidence, LineageHint};
pub use rate_limit::{current_bucket, RateLimit, RateLimitError};
