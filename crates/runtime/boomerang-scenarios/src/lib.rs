#![forbid(unsafe_code)]

//! Deterministic scenario builders for Boomerang development and smoke testing.
//!
//! # Why this exists
//! Topology generation is a different concern from runtime execution. Keeping it in its own crate
//! lets supervisors, examples, and tests share the same deterministic manifest builder.
//!
//! # Role in the system
//! `poc-runtime`, integration tests, and future supervisors use this crate to construct the local
//! 41-process topology before handing the resulting manifest to `boomerang-config` and
//! `boomerang-runtime`.

mod local_poc;

pub use local_poc::{
    LocalPocPublishedIdentities, default_node_bin, default_state_root, local_poc_cluster_manifest,
    local_poc_identity_processes,
};
