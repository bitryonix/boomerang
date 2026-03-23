#![forbid(unsafe_code)]

//! `poc-steps` binary bootstrap.
//!
//! # Why this exists
//! This root stays intentionally small so the legacy step-by-step runner can keep its bootstrap,
//! tracing, and workflow orchestration in focused sibling modules instead of growing another
//! mixed-responsibility entrypoint.
//!
//! # Role in the system
//! `poc-steps` remains a legacy reference runner that exercises setup and withdrawal in one
//! process for debugging and historical comparison with the newer multi-process runtime.
//!
//! # Examples
//! Run the legacy single-process ceremony walkthrough:
//!
//! ```text
//! cargo run -p poc-steps
//! ```

mod app;
mod tracing_setup;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_setup::init_tracing();
    app::run().await
}
