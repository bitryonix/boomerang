#![forbid(unsafe_code)]

//! `boomerang-node` binary bootstrap.
//!
//! # Why this exists
//! This file keeps the binary root intentionally thin so the command model, tracing setup,
//! and runtime orchestration can live in focused modules that are easier to test and document.
//!
//! # Role in the system
//! `boomerang-node` is the supported CLI host for standalone Boomerang role processes and
//! manifest-driven clusters.
//!
//! # Examples
//! Run one role process from a TOML process manifest:
//!
//! ```text
//! cargo run -p boomerang-node -- wt run --config /path/to/wt.toml
//! ```

mod app;
mod cli;
mod tracing_setup;

use clap::Parser;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), boomerang_runtime::RuntimeError> {
    tracing_setup::init_tracing();
    app::run(cli::Cli::parse()).await
}
