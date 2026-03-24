//! Application orchestration for the `poc-runtime` crate.
//!
//! # Why this exists
//! The PoC launcher owns several bootstrapping steps: validating defaults, starting a local
//! Bitcoin Core node, prelaunching WT/SAR so they can publish public ids, generating a
//! deterministic cluster manifest, and launching the remaining child processes. Keeping that
//! orchestration out of `main.rs` keeps the binary thin and reusable from tests and other library
//! call sites.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use boomerang_config::{ClusterManifest, NetworkedPocConfig, ProcessConfig, save_cluster_manifest};
use boomerang_scenarios::local_poc_cluster_manifest;
use corepc_node::{Conf, Node, P2P};
use protocol::constructs::BitcoinCoreAuth;
use protocol_wire::control::TransportRole;
use tracing::info;

use crate::{
    Cli,
    identity::prepare_local_poc_identities,
    launcher::{spawn_processes, supervise_children, terminate_children},
    managed_node_preflight::refresh_workspace_managed_node_if_needed,
    progress_monitor::print_narrative,
};

/// Builds the local POC manifest and launches the full development cluster.
///
/// # Why this exists
/// The 41-process local topology is deterministic, but creating it still requires runtime inputs
/// such as a writable state root, a node binary path, a local Bitcoin Core instance, and
/// the public WT/SAR ids published by the WT/SAR process hosts.
///
/// # Role in the system
/// Called by the `poc-runtime` binary after tracing bootstrap and CLI parsing complete.
///
/// # Errors
/// Returns an error if default POC validation fails, if the local Bitcoin Core node cannot start,
/// if WT/SAR prelaunch fails to publish public ids, if manifest generation or persistence fails,
/// or if any child process fails.
pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let state_root_plan = plan_state_root(&cli)?;
    let config = NetworkedPocConfig::default();
    config.validate()?;
    if state_root_plan.actual_state_root != cli.state_root {
        print_narrative(
            "bootstrap",
            &format!(
                "using run state root {}",
                state_root_plan.actual_state_root.display()
            ),
        );
    }
    refresh_workspace_managed_node_if_needed(&cli.node_bin).await?;
    let result = run_with_state_root(&cli, &state_root_plan.actual_state_root, &config).await;
    report_state_root_after_run(&state_root_plan, result.is_err());
    result
}

async fn run_with_state_root(
    cli: &Cli,
    state_root: &Path,
    config: &NetworkedPocConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    print_narrative(
        "bootstrap",
        "validating defaults and starting the local Bitcoin Core fixture",
    );

    let mut node_conf = Conf::default();
    node_conf.p2p = P2P::Yes;
    let bitcoin_node = Node::with_conf(&config.boomerang.bitcoind_executable_path, &node_conf)?;
    bitcoin_node.p2p_connect(true);

    let rpc_client_url = bitcoin_node.params.rpc_socket;
    let rpc_client_auth = BitcoinCoreAuth::CookieFile(bitcoin_node.params.cookie_file.clone());
    let prepared_identities = prepare_local_poc_identities(
        config,
        state_root,
        cli.base_port,
        rpc_client_url,
        rpc_client_auth.clone(),
        &cli.node_bin,
    )
    .await?;

    print_narrative(
        "identity",
        "all WT/SAR public identities are available; generating the final cluster manifest",
    );

    let mut progress_monitor = prepared_identities.progress_monitor;
    let mut children = prepared_identities.children;
    let manifest = match local_poc_cluster_manifest(
        config,
        &prepared_identities.identities,
        state_root,
        cli.base_port,
        rpc_client_url,
        rpc_client_auth,
    ) {
        Ok(manifest) => manifest,
        Err(error) => {
            terminate_children(&mut children).await;
            return Err(Box::new(error));
        }
    };
    let manifest_path = state_root.join("cluster.toml");

    // Persisting the generated manifest gives operators and tests one stable artifact they can
    // inspect when a child process fails later in the startup sequence.
    if let Err(error) = save_cluster_manifest(&manifest_path, &manifest) {
        terminate_children(&mut children).await;
        return Err(Box::new(error));
    }

    let remaining_processes = non_identity_processes(&manifest);
    print_narrative(
        "cluster",
        &format!(
            "wrote final cluster manifest to {}",
            manifest_path.display()
        ),
    );
    print_narrative(
        "cluster",
        &format!(
            "launching the remaining {} processes around the staged WT/SAR hosts",
            remaining_processes.len()
        ),
    );

    info!(
        manifest = %manifest_path.display(),
        node_bin = %cli.node_bin.display(),
        process_count = manifest.processes.len(),
        remaining_process_count = remaining_processes.len(),
        "launching remaining local Boomerang POC processes after WT/SAR identity publication",
    );

    match spawn_processes(&cli.node_bin, &remaining_processes).await {
        Ok(mut remaining_children) => {
            progress_monitor.add_children(&remaining_children);
            children.append(&mut remaining_children);
            supervise_children(children, &mut progress_monitor).await?;
            Ok(())
        }
        Err(error) => {
            terminate_children(&mut children).await;
            Err(Box::new(error))
        }
    }
}

#[derive(Debug, Clone)]
struct StateRootPlan {
    actual_state_root: PathBuf,
}

/// Resolves the caller's state-root choice into either one fresh per-run child directory or one
/// explicitly persistent exact directory.
fn plan_state_root(cli: &Cli) -> Result<StateRootPlan, StateRootPreflightError> {
    plan_state_root_path(
        &cli.state_root,
        cli.persist_state_root,
        cli.reuse_state_root,
    )
}

fn plan_state_root_path(
    state_root: &Path,
    persist_state_root: bool,
    reuse_state_root: bool,
) -> Result<StateRootPlan, StateRootPreflightError> {
    if !persist_state_root {
        if reuse_state_root {
            return Err(StateRootPreflightError::new(
                state_root,
                "`--reuse-state-root` requires `--persist-state-root`",
            ));
        }

        ensure_state_root_base_ready(state_root)?;
        return Ok(StateRootPlan {
            actual_state_root: fresh_ephemeral_state_root(state_root),
        });
    }

    ensure_persistent_state_root_ready(state_root, reuse_state_root)?;
    Ok(StateRootPlan {
        actual_state_root: state_root.to_path_buf(),
    })
}

/// Verifies that the supplied base directory can host one fresh child run directory.
fn ensure_state_root_base_ready(state_root: &Path) -> Result<(), StateRootPreflightError> {
    if !state_root.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(state_root)
        .map_err(|source| StateRootPreflightError::io(state_root, source))?;
    if !metadata.is_dir() {
        return Err(StateRootPreflightError::new(
            state_root,
            "state-root base exists but is not a directory",
        ));
    }

    Ok(())
}

/// Rejects accidental reuse of an existing non-empty persistent state root unless the operator
/// opted in explicitly.
fn ensure_persistent_state_root_ready(
    state_root: &Path,
    reuse_state_root: bool,
) -> Result<(), StateRootPreflightError> {
    if !state_root.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(state_root)
        .map_err(|source| StateRootPreflightError::io(state_root, source))?;
    if !metadata.is_dir() {
        return Err(StateRootPreflightError::new(
            state_root,
            "persistent state root exists but is not a directory",
        ));
    }

    if reuse_state_root {
        return Ok(());
    }

    let mut entries = fs::read_dir(state_root)
        .map_err(|source| StateRootPreflightError::io(state_root, source))?;
    if entries
        .next()
        .transpose()
        .map_err(|source| StateRootPreflightError::io(state_root, source))?
        .is_some()
    {
        return Err(StateRootPreflightError::new(
            state_root,
            "persistent state root is not empty; use an empty directory or pass --reuse-state-root to opt in",
        ));
    }

    Ok(())
}

/// Creates one unique child run directory path under the configured base path.
fn fresh_ephemeral_state_root(state_root_base: &Path) -> PathBuf {
    state_root_base.join(format!(
        "run-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

/// Reports where the current run left its artifacts.
fn report_state_root_after_run(plan: &StateRootPlan, run_failed: bool) {
    if run_failed {
        print_narrative(
            "artifacts",
            &format!(
                "run artifacts are available at {}",
                plan.actual_state_root.display()
            ),
        );
    } else {
        print_narrative(
            "artifacts",
            &format!("kept run artifacts at {}", plan.actual_state_root.display()),
        );
    }
}

#[derive(Debug)]
struct StateRootPreflightError {
    state_root: PathBuf,
    reason: String,
}

impl StateRootPreflightError {
    fn new(state_root: &Path, reason: impl Into<String>) -> Self {
        Self {
            state_root: state_root.to_path_buf(),
            reason: reason.into(),
        }
    }

    fn io(state_root: &Path, source: std::io::Error) -> Self {
        Self::new(
            state_root,
            format!("failed to inspect the state root: {source}"),
        )
    }
}

impl fmt::Display for StateRootPreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing to use state root {}: {}",
            self.state_root.display(),
            self.reason
        )
    }
}

impl std::error::Error for StateRootPreflightError {}

/// Filters the final cluster manifest down to the processes that were not already prelaunched.
fn non_identity_processes(manifest: &ClusterManifest) -> Vec<ProcessConfig> {
    manifest
        .processes
        .iter()
        .filter(|process| !matches!(process.role, TransportRole::Wt | TransportRole::Sar))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{ensure_persistent_state_root_ready, plan_state_root_path};

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "boomerang-poc-runtime-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn missing_persistent_state_root_is_allowed() {
        let path = unique_temp_path("missing-state-root");
        ensure_persistent_state_root_ready(&path, false)
            .expect("missing persistent state roots should be allowed");
    }

    #[test]
    fn empty_existing_persistent_state_root_is_allowed() {
        let path = unique_temp_path("empty-state-root");
        fs::create_dir_all(&path).expect("empty state root should be created");

        ensure_persistent_state_root_ready(&path, false)
            .expect("empty existing persistent state roots should be allowed");

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn non_empty_persistent_state_root_requires_explicit_opt_in() {
        let path = unique_temp_path("non-empty-state-root");
        fs::create_dir_all(&path).expect("state root should be created");
        fs::write(path.join("progress.log"), "stage=old").expect("test file should be written");

        let error = ensure_persistent_state_root_ready(&path, false)
            .expect_err("non-empty persistent state roots should be rejected without opt-in");
        assert!(error.to_string().contains("--reuse-state-root"));

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn non_empty_persistent_state_root_is_allowed_with_explicit_opt_in() {
        let path = unique_temp_path("reused-state-root");
        fs::create_dir_all(&path).expect("state root should be created");
        fs::write(path.join("progress.log"), "stage=old").expect("test file should be written");

        ensure_persistent_state_root_ready(&path, true)
            .expect("non-empty persistent state roots should be allowed with explicit opt-in");

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn default_mode_uses_fresh_child_directory_under_the_base_path_and_keeps_it() {
        let path = unique_temp_path("ephemeral-base");
        fs::create_dir_all(&path).expect("ephemeral base dir should be created");
        fs::write(path.join("old.txt"), "stale").expect("base dir may already contain old runs");

        let plan = plan_state_root_path(&path, false, false)
            .expect("default mode should accept a non-empty base directory");
        assert_ne!(plan.actual_state_root, path);
        assert_eq!(
            plan.actual_state_root.parent(),
            Some(path.as_path()),
            "fresh run directories should live under the configured base path"
        );

        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn reuse_requires_persistent_state_root_mode() {
        let path = unique_temp_path("reuse-without-persist");

        let error = plan_state_root_path(&path, false, true)
            .expect_err("reusing state roots should require persistent mode");
        assert!(error.to_string().contains("--persist-state-root"));

        let _ = fs::remove_dir_all(path);
    }
}
