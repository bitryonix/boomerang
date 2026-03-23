#![forbid(unsafe_code)]

//! `poc-networked` binary bootstrap.
//!
//! # Why this exists
//! This root stays intentionally small so the legacy channel-based runtime can keep transport
//! wiring, config validation, and tracing bootstrap in focused modules instead of another large
//! entrypoint file.
//!
//! # Role in the system
//! `poc-networked` remains a legacy reference runner for the original Tokio-channel orchestration
//! path while the newer standalone-process runtime evolves.
//!
//! # Examples
//! Run the legacy channel-based proof of concept:
//!
//! ```text
//! cargo run -p poc-networked
//! ```

mod actors;
mod app;
mod envelopes;
mod local_actor;
mod tracing_setup;
mod transport;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_setup::init_tracing();
    app::run().await
}
