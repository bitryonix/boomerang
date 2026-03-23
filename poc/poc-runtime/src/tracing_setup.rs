//! Tracing bootstrap for the preferred `poc-runtime` supervisor.

use tracing_subscriber::EnvFilter;

/// Initializes tracing for the local POC supervisor.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            // The default terminal experience comes from the curated narrative printer, not from
            // raw supervisor tracing. `RUST_LOG` can still opt back into detailed diagnostics.
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .try_init();
}
