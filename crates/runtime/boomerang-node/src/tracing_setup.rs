//! Tracing bootstrap for the `boomerang-node` binary.
//!
//! # Why this exists
//! CLI parsing, runtime orchestration, and subscriber initialization change for different reasons.
//! Keeping tracing setup isolated lets the binary root stay small and makes logging policy easy to
//! adjust without touching the command model.
//!
//! # Role in the system
//! [`init_tracing`] is called exactly once by [`crate::main`] before any runtime work starts.

use tracing_subscriber::EnvFilter;

/// Initializes the default tracing subscriber for the binary.
///
/// # Why this exists
/// `boomerang-node` is an operational binary, so it needs structured logs before config loading or
/// process startup can fail.
///
/// # Role in the system
/// Called by the binary root during process bootstrap.
///
/// # Errors
/// This function intentionally ignores the `try_init` error because tests and embedded launches may
/// have already installed a subscriber. In that case the process can still continue safely.
pub(crate) fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            // Falling back to `info` keeps the binary observable even when `RUST_LOG` is absent or
            // malformed, which is especially helpful for local development and child-process runs.
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}
