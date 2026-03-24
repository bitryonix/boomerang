#![forbid(unsafe_code)]

//! Operator-facing local PoC runtime launcher and examples.
//!
//! # Why this exists
//! The workspace needs one obvious home for the supported 41-process development flow without
//! turning the reusable scenario-builder crate into a supervisor/CLI crate.
//!
//! # Role in the system
//! [`crate`] owns the PoC-specific command surface and exposes the small set of material helpers
//! that its binary and example programs actually reuse, while delegating manifest construction to
//! `boomerang-scenarios` and runtime supervision to `boomerang-runtime`.
//! The package lives in `poc/poc-runtime/` so the top-level `poc/` area can also hold the legacy
//! PoC runners that still matter as reference surfaces.

mod app;
mod cli;
mod identity;
mod launcher;
mod managed_node_preflight;
mod progress_monitor;
mod tracing_setup;

pub use app::run;
pub use boomerang_scenarios::{
    LocalPocPublishedIdentities, default_node_bin, default_state_root, local_poc_cluster_manifest,
    local_poc_identity_processes,
};
pub use cli::Cli;
pub use tracing_setup::init_tracing;
