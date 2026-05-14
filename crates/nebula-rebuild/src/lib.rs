//! NebulaCR auto-rebuild on base CVE patch.
//!
//! Slice 1 ships the lineage extractor (label-based + history-based)
//! and the schema. The subscription reconciler + emitters
//! (GitHub/GitLab/Tekton/webhook) ship in slices 2-3.

pub mod emitter;
pub mod lineage;
pub mod rate_limit;

pub use emitter::{
    EmitError, GenericWebhookEmitter, GitHubDispatchEmitter, GitLabPipelineEmitter, RebuildEmitter,
    RebuildEvent, TektonEventListenerEmitter, TriggerCause, compute_webhook_signature,
};
pub use lineage::{LineageConfidence, LineageHint, detect_lineage};
pub use rate_limit::{RateLimit, RateLimitError, current_bucket};
