//! Tracing bootstrap for the legacy `poc-networked` binary.
//!
//! # Why this exists
//! Logging setup changes for different reasons than actor wiring. Keeping it separate makes the
//! binary root stay bootstrap-only and easier to audit.
//!
//! # Role in the system
//! [`init_tracing`] is called once by [`crate::main`] before any actor startup begins.

use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Installs the tracing subscriber for the legacy concurrent runner.
///
/// # Why this exists
/// The channel-based proof of concept is hard to debug without startup logs, so it installs
/// tracing before config loading or actor wiring can fail.
///
/// # Role in the system
/// Called once by the binary root during process bootstrap.
///
/// # Errors
/// Subscriber installation is intentionally best-effort because tests or embedding harnesses may
/// already have installed a global subscriber.
pub(crate) fn init_tracing() {
    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into());
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .pretty()
        .finish();

    // Ignoring duplicate-subscriber installation keeps legacy smoke tests and embedded launches
    // from failing only because tracing was initialized earlier in the same process.
    let _ = tracing::subscriber::set_global_default(subscriber);
}
