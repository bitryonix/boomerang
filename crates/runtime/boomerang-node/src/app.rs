//! Application orchestration for the `boomerang-node` binary.
//!
//! # Why this exists
//! Command parsing and runtime orchestration change for different reasons. This module keeps the
//! command model in [`crate::cli`] and the runtime bootstrap logic here so each stays focused.
//!
//! # Role in the system
//! [`run`] is the single entrypoint used by the binary root after clap parsing succeeds.

use std::path::Path;

use boomerang_config::{load_cluster_manifest, load_process_config};
use boomerang_runtime::{RuntimeError, launch_cluster_async, run_process_async};
use protocol_wire::control::TransportRole;

use crate::cli::{Cli, CliCommand, ClusterAction, ClusterCommand, RoleAction, RoleCommand};

/// Runs the parsed `boomerang-node` command.
///
/// # Why this exists
/// The binary root should only parse CLI arguments and initialize tracing. This function owns the
/// command-to-service dispatch so the bootstrap stays small and testable.
///
/// # Role in the system
/// Called by [`crate::main`] after clap has produced a validated [`Cli`] value.
///
/// # Errors
/// Returns [`RuntimeError`] when config loading fails, when the requested CLI role does not match
/// the process manifest, or when runtime startup/cluster launch fails.
///
/// # Examples
/// The canonical story is a developer starting one WT process:
///
/// ```text
/// boomerang-node wt run --config /tmp/wt.toml
/// ```
pub(crate) async fn run(cli: Cli) -> Result<(), RuntimeError> {
    match cli.command {
        CliCommand::Wt(command) => run_role(TransportRole::Wt, command).await,
        CliCommand::Sar(command) => run_role(TransportRole::Sar, command).await,
        CliCommand::Peer(command) => run_role(TransportRole::Peer, command).await,
        CliCommand::Niso(command) => run_role(TransportRole::Niso, command).await,
        CliCommand::Iso(command) => run_role(TransportRole::Iso, command).await,
        CliCommand::Boomlet(command) => run_role(TransportRole::Boomlet, command).await,
        CliCommand::Phone(command) => run_role(TransportRole::Phone, command).await,
        CliCommand::St(command) => run_role(TransportRole::St, command).await,
        CliCommand::Cluster(command) => run_cluster(command).await,
    }
}

/// Loads a process config for one role and runs it.
///
/// # Why this exists
/// The CLI exposes role names directly, but the manifest is still the source of truth for the
/// actual role configuration. This function keeps that consistency check at the binary boundary.
///
/// # Role in the system
/// Used for every `<role> run --config ...` path.
///
/// # Errors
/// Returns an error if the process config cannot be loaded, if the config advertises a different
/// role than the CLI path selected, or if the runtime process returns an operational error.
pub(crate) async fn run_role(
    expected_role: TransportRole,
    command: RoleCommand,
) -> Result<(), RuntimeError> {
    match command.action {
        RoleAction::Run { config } => {
            let process = load_process_config(&config)?;
            if process.role != expected_role {
                // The CLI role is treated as an operator intent check so we fail fast before the
                // wrong process starts with a misleading command name.
                return Err(RuntimeError::ConfigRoleMismatch {
                    expected: expected_role,
                    actual: process.role,
                });
            }
            run_process_async(process).await
        }
    }
}

/// Executes a cluster-level command.
///
/// # Why this exists
/// Cluster orchestration has a different lifecycle from single-process execution, so it is kept in
/// its own function rather than buried inside the role match.
pub(crate) async fn run_cluster(command: ClusterCommand) -> Result<(), RuntimeError> {
    match command.action {
        ClusterAction::Up { manifest } => cluster_up(&manifest).await,
    }
}

/// Loads one cluster manifest and launches it with the current binary executable.
///
/// # Why this exists
/// Child processes should be spawned through the same executable that the operator invoked, which
/// avoids drift between development and packaged paths.
///
/// # Role in the system
/// This is the implementation behind `boomerang-node cluster up --manifest ...`.
///
/// # Errors
/// Returns an error if the manifest cannot be loaded, if the current executable path cannot be
/// determined, or if the child-process launcher fails.
pub(crate) async fn cluster_up(manifest_path: &Path) -> Result<(), RuntimeError> {
    let manifest = load_cluster_manifest(manifest_path)?;

    // Reusing the currently running executable keeps cluster launches aligned with the exact build
    // the operator invoked, which avoids path drift between direct runs and spawned children.
    let current_exe = std::env::current_exe()?;
    launch_cluster_async(&current_exe, &manifest).await
}

#[cfg(test)]
mod tests {
    //! Smoke tests for the checked-in operator examples.

    use std::path::PathBuf;

    use protocol_wire::control::TransportRole;

    use super::{load_cluster_manifest, load_process_config};

    fn example_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(file_name)
    }

    #[test]
    fn checked_in_minimal_process_example_loads() {
        let example = example_path("minimal-process.toml");
        let process = load_process_config(&example).unwrap_or_else(|error| {
            panic!("expected minimal-process.toml to stay loadable: {error}")
        });

        assert_eq!(process.role, TransportRole::St);
    }

    #[test]
    fn checked_in_minimal_cluster_example_loads() {
        let example = example_path("minimal-cluster.toml");
        let manifest = load_cluster_manifest(&example).unwrap_or_else(|error| {
            panic!("expected minimal-cluster.toml to stay loadable: {error}")
        });

        assert_eq!(manifest.processes.len(), 2);
    }
}
