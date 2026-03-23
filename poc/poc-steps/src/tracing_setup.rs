//! Tracing bootstrap for the legacy `poc-steps` binary.
//!
//! # Why this exists
//! Logging policy changes for different reasons than workflow orchestration. Keeping tracing setup
//! in its own module lets the binary root stay bootstrap-only.
//!
//! # Role in the system
//! [`init_tracing`] is called once by [`crate::main`] before the legacy walkthrough starts.

use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Installs the tracing subscriber used by the legacy single-process walkthrough.
///
/// # Why this exists
/// Setup and withdrawal failures are difficult to diagnose without logs, so the runner installs a
/// subscriber before config loading or protocol execution can fail.
///
/// # Role in the system
/// Called exactly once during process bootstrap.
///
/// # Errors
/// Subscriber installation is intentionally best-effort. Tests may have already configured
/// tracing, and that should not stop the legacy walkthrough from running.
///
/// # Examples
/// The binary root calls this before delegating to [`crate::app::run`].
pub(crate) fn init_tracing() {
    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into());
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .pretty()
        .finish();

    // The legacy runner is often embedded inside tests or other developer flows that already have
    // a global subscriber, so we deliberately ignore the duplicate-install error.
    let _ = tracing::subscriber::set_global_default(subscriber);
}
