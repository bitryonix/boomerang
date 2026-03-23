//! WT/SAR prelaunch helpers for the supported local PoC launcher.
//!
//! # Why this exists
//! Peers need WT/SAR public ids before the full cluster manifest can be assembled, but only the
//! WT/SAR processes themselves are allowed to create their private identity material. The PoC
//! therefore starts the real WT/SAR processes first and waits for their published public ids.

use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    path::Path,
    time::{Duration, Instant},
};

use boomerang_config::{
    NetworkedPocConfig, ProcessConfig, PublishedProcessIdentity, load_published_process_identity,
    published_identity_path,
};
use boomerang_runtime::RuntimeError;
use boomerang_scenarios::{LocalPocPublishedIdentities, local_poc_identity_processes};
use protocol::constructs::BitcoinCoreAuth;
use tracing::info;

use crate::launcher::{
    CHILD_EXIT_POLL_DELAY, RunningChild, ensure_children_still_running, spawn_processes,
    terminate_children,
};
use crate::progress_monitor::{NarrativeProgressMonitor, print_narrative};

/// Maximum time the PoC launcher waits for WT/SAR public identity artifacts to appear.
const PUBLISHED_IDENTITY_TIMEOUT: Duration = Duration::from_secs(30);

/// Tracks the stage-one WT/SAR children together with the public ids they published.
pub(crate) struct PreparedIdentityStage {
    pub(crate) identities: LocalPocPublishedIdentities,
    pub(crate) children: Vec<RunningChild>,
    pub(crate) progress_monitor: NarrativeProgressMonitor,
}

/// Starts WT/SAR processes, waits for their public ids, and keeps those processes running.
pub(crate) async fn prepare_local_poc_identities(
    config: &NetworkedPocConfig,
    state_root: &Path,
    base_port: u16,
    rpc_client_url: std::net::SocketAddrV4,
    rpc_client_auth: BitcoinCoreAuth,
    node_bin: &Path,
) -> Result<PreparedIdentityStage, RuntimeError> {
    print_narrative(
        "identity",
        "starting WT/SAR first so they can publish the public identities the cluster needs",
    );
    let processes = local_poc_identity_processes(
        config,
        state_root,
        base_port,
        rpc_client_url,
        rpc_client_auth,
    )?;
    clear_stale_published_identities(&processes)?;
    let mut children = spawn_processes(node_bin, &processes).await?;
    let mut progress_monitor = NarrativeProgressMonitor::from_children(&children);

    match wait_for_published_identities(&processes, &mut children, &mut progress_monitor).await {
        Ok(identities) => Ok(PreparedIdentityStage {
            identities,
            children,
            progress_monitor,
        }),
        Err(error) => {
            terminate_children(&mut children).await;
            Err(error)
        }
    }
}

/// Removes stale published-identity artifacts so one PoC run never consumes another run's ids.
fn clear_stale_published_identities(processes: &[ProcessConfig]) -> Result<(), RuntimeError> {
    for process in processes {
        let published_path = published_identity_path(&process.state_dir);
        match fs::remove_file(&published_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

/// Waits until every staged WT/SAR process has published its public identity artifact.
async fn wait_for_published_identities(
    processes: &[ProcessConfig],
    children: &mut Vec<RunningChild>,
    progress_monitor: &mut NarrativeProgressMonitor,
) -> Result<LocalPocPublishedIdentities, RuntimeError> {
    let deadline = Instant::now() + PUBLISHED_IDENTITY_TIMEOUT;

    loop {
        progress_monitor.poll().await?;
        ensure_children_still_running(children).await?;

        if let Some(identities) = try_collect_published_identities(processes)? {
            return Ok(identities);
        }

        if Instant::now() >= deadline {
            let pending_processes = processes
                .iter()
                .filter_map(|process| {
                    let path = published_identity_path(&process.state_dir);
                    (!path.exists()).then_some(format!(
                        "{}:{} ({})",
                        process.role.as_str(),
                        process.instance_id,
                        path.display()
                    ))
                })
                .collect::<Vec<_>>()
                .join(", ");
            return Err(RuntimeError::PublishedIdentityTimedOut { pending_processes });
        }

        tokio::time::sleep(CHILD_EXIT_POLL_DELAY).await;
    }
}

/// Attempts one non-blocking collection pass over the expected WT/SAR public identity files.
fn try_collect_published_identities(
    processes: &[ProcessConfig],
) -> Result<Option<LocalPocPublishedIdentities>, RuntimeError> {
    let mut wt_id = None;
    let mut sar_ids_by_instance = BTreeMap::new();

    for process in processes {
        let path = published_identity_path(&process.state_dir);
        let identity = match load_published_process_identity(&path) {
            Ok(identity) => identity,
            Err(boomerang_config::RuntimeConfigError::ReadConfigFile { source, .. })
                if source.kind() == ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };

        match identity {
            PublishedProcessIdentity::Wt {
                wt_id: published_wt_id,
            } => {
                info!(
                    instance_id = process.instance_id,
                    role = process.role.as_str(),
                    path = %path.display(),
                    "collected published WT identity artifact",
                );
                wt_id = Some(published_wt_id);
            }
            PublishedProcessIdentity::Sar { sar_id } => {
                info!(
                    instance_id = process.instance_id,
                    role = process.role.as_str(),
                    path = %path.display(),
                    "collected published SAR identity artifact",
                );
                sar_ids_by_instance.insert(process.instance_id.clone(), sar_id);
            }
        }
    }

    Ok(wt_id.map(|wt_id| LocalPocPublishedIdentities::new(wt_id, sar_ids_by_instance)))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use boomerang_config::{
        BoomerangNetworkConfig, ProcessBootstrap, ProcessConfig, ProcessRoutes, WithdrawalConfig,
    };
    use protocol_wire::control::TransportRole;

    use super::clear_stale_published_identities;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
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
    fn clears_old_published_identity_artifacts_before_stage_one() {
        let state_dir = unique_temp_dir("identity-cleanup");
        fs::create_dir_all(&state_dir).expect("temporary state dir should be created");
        let published_path = boomerang_config::published_identity_path(&state_dir);
        fs::write(&published_path, "kind = \"wt\"\n")
            .expect("stale published identity should exist");

        let process = ProcessConfig {
            role: TransportRole::Wt,
            instance_id: "wt-1".to_owned(),
            state_dir: state_dir.clone(),
            bootstrap: ProcessBootstrap::Wt {
                rpc_client_url: std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 18443),
                rpc_client_auth: protocol::constructs::BitcoinCoreAuth::None,
            },
            routes: ProcessRoutes::Wt {
                peer_links: std::collections::BTreeMap::new(),
                sar_links: std::collections::BTreeMap::new(),
            },
            links: Vec::new(),
            boomerang: BoomerangNetworkConfig::default(),
            withdrawal: WithdrawalConfig::default(),
        };

        clear_stale_published_identities(&[process])
            .expect("cleanup should remove stale published identity files");
        assert!(!published_path.exists());

        let _ = fs::remove_dir_all(state_dir);
    }
}
