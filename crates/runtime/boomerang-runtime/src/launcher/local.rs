//! Local child-process launcher used by the supported runtime path.

use std::{fs::OpenOptions, path::Path, process::Stdio, time::Duration};

use boomerang_config::{ClusterManifest, ProcessConfig};
use protocol_wire::control::TransportRole;
use tracing::info;

use crate::{
    error::RuntimeError,
    launcher::{
        api::{ClusterLaunchFuture, ClusterLauncher},
        service::{log_path_for_process, write_cluster_process_configs},
    },
};

/// Delay between child exit polls while the local launcher supervises a cluster.
const CHILD_EXIT_POLL_DELAY: Duration = Duration::from_millis(200);

/// Concrete launcher that spawns one local child process per manifest entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalChildLauncher;

/// Tracks one running child while the launcher supervises the cluster.
struct RunningChild {
    role: TransportRole,
    instance_id: String,
    child: tokio::process::Child,
}

impl ClusterLauncher for LocalChildLauncher {
    fn launch_cluster<'a>(
        &'a self,
        node_bin: &'a Path,
        manifest: &'a ClusterManifest,
    ) -> ClusterLaunchFuture<'a> {
        Box::pin(async move {
            let mut children = spawn_cluster(node_bin, manifest).await?;
            let mut tick = tokio::time::interval(CHILD_EXIT_POLL_DELAY);

            loop {
                tick.tick().await;

                let mut index = 0;
                while index < children.len() {
                    if let Some(status) = children[index].child.try_wait()? {
                        let exited = children.swap_remove(index);

                        if status.success() {
                            info!(
                                role = exited.role.as_str(),
                                instance_id = exited.instance_id,
                                exit_code = status.code(),
                                remaining_children = children.len(),
                                "boomerang node child exited cleanly",
                            );
                            if children.is_empty() {
                                return Ok(());
                            }
                            continue;
                        }

                        terminate_children(&mut children).await;
                        return Err(RuntimeError::ChildProcessExited {
                            role: exited.role,
                            instance_id: exited.instance_id,
                            exit_code: status.code(),
                        });
                    }

                    index += 1;
                }
            }
        })
    }
}

/// Spawns the local child processes for one manifest.
async fn spawn_cluster(
    node_bin: &Path,
    manifest: &ClusterManifest,
) -> Result<Vec<RunningChild>, RuntimeError> {
    let written = write_cluster_process_configs(manifest)?;
    let mut children = Vec::with_capacity(written.len());

    for (process, config_path) in written {
        let log_path = log_path_for_process(&process);
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let stderr_log = log_file.try_clone()?;

        info!(
            role = process.role.as_str(),
            instance_id = process.instance_id,
            config = %config_path.display(),
            log = %log_path.display(),
            node_bin = %node_bin.display(),
            "spawning boomerang node child",
        );

        let child = spawn_child_process(node_bin, &process, &config_path, log_file, stderr_log)?;

        children.push(RunningChild {
            role: process.role,
            instance_id: process.instance_id,
            child,
        });
    }

    Ok(children)
}

async fn terminate_children(children: &mut [RunningChild]) {
    for child in children.iter_mut() {
        let _ = child.child.start_kill();
    }
    for child in children.iter_mut() {
        let _ = child.child.wait().await;
    }
}

/// Spawns one `boomerang-node` child process from a written process config.
fn spawn_child_process(
    node_bin: &Path,
    process: &ProcessConfig,
    config_path: &Path,
    stdout_log: std::fs::File,
    stderr_log: std::fs::File,
) -> Result<tokio::process::Child, RuntimeError> {
    Ok(tokio::process::Command::new(node_bin)
        .arg(process.role.as_str())
        .arg("run")
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()?)
}
