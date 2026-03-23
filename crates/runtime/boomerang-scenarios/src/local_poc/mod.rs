//! Deterministic local 41-process POC topology generation.
//!
//! # Why this exists
//! The repository's supported smoke path depends on a fixed topology with predictable identities,
//! routes, and loopback ports. This module keeps those rules in one place instead of spreading
//! them across the CLI and tests.

mod builder;
mod draft;
mod error;
mod identity;
mod ids;
mod links;
mod ports;
#[cfg(test)]
mod tests;

pub use builder::local_poc_identity_processes;
pub use builder::{default_node_bin, default_state_root, local_poc_cluster_manifest};
pub use identity::LocalPocPublishedIdentities;
