//! Built-in tool implementations.
//!
//! Slice 1 ships read-only tools that don't depend on other in-flight
//! crates yet. Each tool is a small struct that takes a Postgres pool
//! at construction time and reads from existing tables.

pub mod ping;

pub use ping::PingTool;
