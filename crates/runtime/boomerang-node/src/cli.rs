//! CLI model for the `boomerang-node` binary.
//!
//! # Why this exists
//! The runtime host accepts several closely related role subcommands. Keeping the clap model in a
//! dedicated module makes the binary root easier to scan and lets tests focus on command parsing
//! without pulling in runtime behavior.
//!
//! # Role in the system
//! [`Cli`] is parsed by [`crate::main`] and then handed to [`crate::app::run`] for execution.
//!
//! # Examples
//! An operator can point the WT host at one process config:
//!
//! ```text
//! boomerang-node wt run --config /tmp/wt.toml
//! ```

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Top-level CLI entrypoint for `boomerang-node`.
///
/// # Why this exists
/// The binary supports both one-role execution and cluster launching. This wrapper keeps those
/// entrypoints explicit and versionable.
///
/// # Role in the system
/// [`crate::app::run`] matches on this command tree to decide which runtime service to invoke.
///
/// # Errors
/// Clap rejects invalid flag combinations or unknown subcommands before runtime code runs.
///
/// # Examples
/// Start one peer process:
///
/// ```text
/// boomerang-node peer run --config /tmp/peer.toml
/// ```
#[derive(Debug, Parser)]
#[command(name = "boomerang-node")]
#[command(about = "Standalone Boomerang entity host over ProtocolFrame transport")]
pub(crate) struct Cli {
    /// The role-specific or cluster-wide command to execute.
    #[command(subcommand)]
    pub(crate) command: CliCommand,
}

/// Supported top-level `boomerang-node` commands.
///
/// # Why this exists
/// Each role process shares the same binary bootstrap, but cluster launching needs a distinct
/// control path. This enum keeps those paths explicit and testable.
///
/// # Role in the system
/// [`crate::app::run`] translates each variant into a concrete runtime action.
#[derive(Debug, Subcommand)]
pub(crate) enum CliCommand {
    /// Run a watchtower process from a process manifest.
    Wt(RoleCommand),
    /// Run a search-and-rescue process from a process manifest.
    Sar(RoleCommand),
    /// Run a peer process from a process manifest.
    Peer(RoleCommand),
    /// Run a non-initiator signer process from a process manifest.
    Niso(RoleCommand),
    /// Run an initiator signer process from a process manifest.
    Iso(RoleCommand),
    /// Run a boomlet process from a process manifest.
    Boomlet(RoleCommand),
    /// Run a phone process from a process manifest.
    Phone(RoleCommand),
    /// Run a safety token process from a process manifest.
    St(RoleCommand),
    /// Launch a manifest-defined cluster of child processes.
    Cluster(ClusterCommand),
}

/// Wrapper for subcommands that target a single process role.
///
/// # Why this exists
/// Role processes currently share one action shape, but keeping that action nested gives the CLI
/// room to grow without breaking the top-level role names.
#[derive(Debug, Args)]
pub(crate) struct RoleCommand {
    /// The role action to execute.
    #[command(subcommand)]
    pub(crate) action: RoleAction,
}

/// Actions that can be executed for one process role.
#[derive(Debug, Subcommand)]
pub(crate) enum RoleAction {
    /// Load a process config and run that role until completion or error.
    ///
    /// WT and SAR create identity internally during `run` and publish only `identity-public.toml`
    /// back into their `state_dir` for supervisors to consume.
    Run {
        /// Path to the TOML process configuration file.
        #[arg(long)]
        config: PathBuf,
    },
}

/// Wrapper for cluster-level commands.
#[derive(Debug, Args)]
pub(crate) struct ClusterCommand {
    /// The cluster action to execute.
    #[command(subcommand)]
    pub(crate) action: ClusterAction,
}

/// Actions that affect a full cluster of processes.
#[derive(Debug, Subcommand)]
pub(crate) enum ClusterAction {
    /// Launch the processes declared by one cluster manifest.
    Up {
        /// Path to the TOML cluster manifest.
        #[arg(long)]
        manifest: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    //! Parsing tests for the `boomerang-node` command tree.

    use std::path::PathBuf;

    use clap::Parser;

    use super::{Cli, CliCommand, ClusterAction, ClusterCommand, RoleAction, RoleCommand};

    /// Verifies the role command shape stays stable for process-manifest execution.
    #[test]
    fn clap_parses_role_run_command() {
        let cli = Cli::try_parse_from(["boomerang-node", "wt", "run", "--config", "/tmp/wt.toml"])
            .expect("the WT run command should remain parseable");

        let parsed_path = match cli.command {
            CliCommand::Wt(RoleCommand {
                action: RoleAction::Run { config },
            }) => config,
            other => panic!("expected WT run command, got {other:?}"),
        };

        assert_eq!(parsed_path, PathBuf::from("/tmp/wt.toml"));
    }

    /// Verifies the cluster launcher flag remains stable for supervisor integrations.
    #[test]
    fn clap_parses_cluster_up_command() {
        let cli = Cli::try_parse_from([
            "boomerang-node",
            "cluster",
            "up",
            "--manifest",
            "/tmp/cluster.toml",
        ])
        .expect("the cluster up command should remain parseable");

        let parsed_path = match cli.command {
            CliCommand::Cluster(ClusterCommand {
                action: ClusterAction::Up { manifest },
            }) => manifest,
            other => panic!("expected cluster up command, got {other:?}"),
        };

        assert_eq!(parsed_path, PathBuf::from("/tmp/cluster.toml"));
    }
}
