//! Workflow orchestration for the legacy `poc-steps` binary.
//!
//! # Why this exists
//! The binary root should only install tracing and delegate. This module keeps config loading,
//! operator-facing startup output, and the sequential setup/withdrawal walkthrough together.
//!
//! # Role in the system
//! [`run`] is the single entrypoint used by [`crate::main`] after tracing is ready.

use boomerang_config::{ConfigError, PocStepsConfig};
use poc_steps::{setup, withdrawal};

/// Runs the legacy single-process setup and withdrawal walkthrough.
///
/// # Why this exists
/// The historical `poc-steps` binary is still useful as a deterministic reference path when we
/// compare newer orchestration layers against the original step-by-step ceremony flow.
///
/// # Role in the system
/// Called only by [`crate::main`] after tracing bootstrap.
///
/// # Errors
/// Returns an error when the default config is invalid, when setup fails, or when the withdrawal
/// walkthrough fails.
///
/// # Examples
/// The canonical operator story is a developer validating the full legacy walkthrough locally:
///
/// ```text
/// cargo run -p poc-steps
/// ```
pub(crate) async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    print_milestones(&config);

    // The setup output is the state handoff that the withdrawal walkthrough consumes, so we keep
    // both phases in one function to make that dependency explicit for maintainers.
    let boomerang_entities = setup::run(&config.boomerang)?;
    withdrawal::run(boomerang_entities, &config.boomerang, &config.withdrawal).await?;

    Ok(())
}

/// Loads and validates the default legacy runner configuration.
///
/// # Why this exists
/// The legacy binary still needs the same fail-fast boundary validation as the maintained runtime
/// path, even though it currently relies on in-repo defaults instead of external manifests.
///
/// # Role in the system
/// Used by [`run`] before any setup or withdrawal side effects begin.
///
/// # Errors
/// Returns [`ConfigError`] when the default config violates the shared POC invariants.
///
/// # Examples
/// The canonical unit-level story is checking that the baked-in defaults are still coherent:
///
/// ```text
/// let config = load_config()?;
/// ```
pub(crate) fn load_config() -> Result<PocStepsConfig, ConfigError> {
    let config = PocStepsConfig::default();
    config.validate()?;
    Ok(config)
}

/// Prints the milestone summary that operators expect before the walkthrough begins.
///
/// # Why this exists
/// These values help developers correlate protocol logs with the configured block-height windows
/// before the step-by-step ceremony starts mutating shared state.
///
/// # Role in the system
/// Called by [`run`] after config validation and before setup.
///
/// # Examples
/// The binary uses this directly before entering the setup flow:
///
/// ```text
/// print_milestones(&config);
/// ```
pub(crate) fn print_milestones(config: &PocStepsConfig) {
    println!(
        "\nBoomerang regime starts at block:     {}",
        config.boomerang.milestone_block_0
    );
    println!(
        "Withdrawal starts at block:           {}",
        config
            .withdrawal
            .absolute_locktime_for_withdrawal_transaction
    );
    println!(
        "Boomerang regime finishes at block:   {}\n",
        config.boomerang.milestone_block_1
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keeps the legacy runner honest by asserting the built-in config still validates.
    #[test]
    fn default_startup_config_is_valid() {
        assert!(load_config().is_ok());
    }
}
