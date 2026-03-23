#![forbid(unsafe_code)]

//! Typed configuration models for Boomerang process and cluster runners.
//!
//! # Why this exists
//! The runtime and scenario crates need one shared place for POC defaults, process manifests,
//! and cluster manifests so they can evolve without each crate inventing its own TOML schema.
//!
//! # Role in the system
//! `boomerang-config` sits between the CLI/supervisor layer and the runtime layer. It owns the
//! configuration vocabulary, validation rules, and TOML load/save helpers consumed by
//! [`boomerang-node`](../../boomerang-node/README.md) and
//! [`poc-runtime`](../../../../poc/poc-runtime/README.md).
//!
//! # Examples
//! A small end-to-end story lives in `examples/manifest_story.rs`. It shows how an operator tool
//! can build a manifest in memory, validate it, and serialize it without starting any processes.

mod poc;
mod runtime;

pub use poc::*;
pub use runtime::*;
