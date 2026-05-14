//! NebulaCR ephemeral repos + TTL tags.
//!
//! Slice 1: TTL header parser, project default cap, schema. The
//! reaper task and SCM webhooks ship in slice 2-3.

pub mod reaper;
pub mod ttl;

pub use reaper::{TtlReaper, TtlReaperConfig, TtlReaperControl, TtlReaperError, TtlReaperStats};
pub use ttl::{parse_ttl_header, TtlError, TtlSpec};
