//! CLI model for the preferred local `poc-runtime` launcher.

use std::path::PathBuf;

use clap::Parser;

use crate::{default_node_bin, default_state_root};

/// Parsed CLI arguments for the local multi-process POC supervisor.
#[derive(Debug, Parser)]
#[command(about = "Launch the 41-process local Boomerang POC cluster over ProtocolFrame TCP links")]
pub struct Cli {
    /// Path to the `boomerang-node` executable that should be spawned for child processes.
    #[arg(long, default_value_os_t = default_node_bin())]
    pub node_bin: PathBuf,
    /// Base directory where a fresh per-run child directory should be created.
    ///
    /// Without `--persist-state-root`, `poc-runtime` creates one fresh `run-*` directory under
    /// this path and keeps it after the run finishes.
    #[arg(long, default_value_os_t = default_state_root())]
    pub state_root: PathBuf,
    /// Use the exact `--state-root` directory instead of creating a fresh `run-*` child under it.
    #[arg(long, default_value_t = false)]
    pub persist_state_root: bool,
    /// Allow reusing an existing non-empty persistent state root from an earlier run.
    #[arg(long, default_value_t = false)]
    pub reuse_state_root: bool,
    /// First TCP port reserved for deterministic loopback link allocation.
    #[arg(long, default_value_t = 24000)]
    pub base_port: u16,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;

    use super::Cli;

    #[test]
    fn clap_parses_custom_values() {
        let cli = Cli::try_parse_from([
            "poc-runtime",
            "--node-bin",
            "/tmp/boomerang-node",
            "--state-root",
            "/tmp/poc-state",
            "--persist-state-root",
            "--reuse-state-root",
            "--base-port",
            "26000",
        ])
        .expect("the local POC CLI should accept explicit bootstrap paths");

        assert_eq!(cli.node_bin, PathBuf::from("/tmp/boomerang-node"));
        assert_eq!(cli.state_root, PathBuf::from("/tmp/poc-state"));
        assert!(cli.persist_state_root);
        assert!(cli.reuse_state_root);
        assert_eq!(cli.base_port, 26000);
    }
}
