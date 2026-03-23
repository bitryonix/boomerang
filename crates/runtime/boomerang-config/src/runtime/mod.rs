//! Process and cluster manifest models plus TOML persistence helpers.
//!
//! # Why this exists
//! Runtime manifests change for different reasons than high-level protocol defaults. This module
//! keeps process wiring, route validation, and TOML I/O together without mixing them into the
//! POC-default models.

mod error;
mod io;
mod model;
#[cfg(test)]
mod tests;
mod validate;

pub use error::RuntimeConfigError;
pub use io::{
    load_cluster_manifest, load_process_config, load_published_process_identity,
    published_identity_path, save_cluster_manifest, save_process_config,
    save_published_process_identity,
};
pub use model::{
    BoomletSlot, ClusterManifest, ProcessBootstrap, ProcessConfig, ProcessRoutes,
    PublishedProcessIdentity,
};
