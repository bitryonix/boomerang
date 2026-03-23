//! Local child-process helpers for the staged PoC launcher.
//!
//! # Why this exists
//! The supported PoC flow starts WT/SAR first, waits for their public ids, then launches the rest
//! of the cluster. That staged supervision does not fit the generic one-shot cluster launcher.

use std::{
    fmt::Write as _,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use boomerang_config::{ProcessConfig, save_process_config};
use boomerang_runtime::RuntimeError;
use protocol_wire::control::TransportRole;
use tracing::info;

use crate::progress_monitor::{NarrativeProgressMonitor, print_failure_summary, print_narrative};

/// Delay between child exit polls while the PoC launcher supervises local processes.
pub(crate) const CHILD_EXIT_POLL_DELAY: Duration = Duration::from_millis(200);

/// Tracks one running child process under PoC supervision.
pub(crate) struct RunningChild {
    pub(crate) role: TransportRole,
    pub(crate) instance_id: String,
    pub(crate) node_log_path: PathBuf,
    pub(crate) progress_log_path: PathBuf,
    pub(crate) child: tokio::process::Child,
}

/// Returns the config path written for one spawned process.
pub(crate) fn process_config_path(process: &ProcessConfig) -> PathBuf {
    process.state_dir.join(format!(
        "{}-{}.toml",
        process.role.as_str(),
        process.instance_id
    ))
}

/// Spawns one local `boomerang-node` child for every supplied process config.
pub(crate) async fn spawn_processes(
    node_bin: &Path,
    processes: &[ProcessConfig],
) -> Result<Vec<RunningChild>, RuntimeError> {
    let mut children = Vec::with_capacity(processes.len());

    for process in processes {
        if let Err(error) = spawn_one_process(node_bin, process).map(|child| children.push(child)) {
            terminate_children(&mut children).await;
            return Err(error);
        }
    }

    Ok(children)
}

/// Kills and waits for every child that is still tracked.
pub(crate) async fn terminate_children(children: &mut [RunningChild]) {
    for child in children.iter_mut() {
        let _ = child.child.start_kill();
    }
    for child in children.iter_mut() {
        let _ = child.child.wait().await;
    }
}

/// Supervises all running children until they either all exit cleanly or one fails.
pub(crate) async fn supervise_children(
    mut children: Vec<RunningChild>,
    progress_monitor: &mut NarrativeProgressMonitor,
) -> Result<(), RuntimeError> {
    let mut tick = tokio::time::interval(CHILD_EXIT_POLL_DELAY);

    loop {
        tick.tick().await;
        progress_monitor.poll().await?;

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
                        "PoC child exited cleanly",
                    );
                    if children.is_empty() {
                        print_narrative(
                            "done",
                            &format!(
                                "all {} managed processes exited cleanly",
                                progress_monitor.expected_processes()
                            ),
                        );
                        return Ok(());
                    }
                    continue;
                }

                print_failure_summary(&exited, status.code());
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
}

/// Fails fast if any tracked child exits during a stage that expects all children to stay alive.
pub(crate) async fn ensure_children_still_running(
    children: &mut Vec<RunningChild>,
) -> Result<(), RuntimeError> {
    let mut index = 0;
    while index < children.len() {
        if let Some(status) = children[index].child.try_wait()? {
            let exited = children.swap_remove(index);
            print_failure_summary(&exited, status.code());
            terminate_children(children).await;
            return Err(RuntimeError::ChildProcessExited {
                role: exited.role,
                instance_id: exited.instance_id,
                exit_code: status.code(),
            });
        }

        index += 1;
    }

    Ok(())
}

/// Spawns one `boomerang-node` child from a written process config.
fn spawn_one_process(
    node_bin: &Path,
    process: &ProcessConfig,
) -> Result<RunningChild, RuntimeError> {
    let config_path = process_config_path(process);
    save_process_config(&config_path, process)?;

    let node_log_path = process.state_dir.join("node.log");
    let progress_log_path = process.state_dir.join("progress.log");
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&node_log_path)?;
    let stderr_log = log_file.try_clone()?;

    info!(
        role = process.role.as_str(),
        instance_id = process.instance_id,
        config = %config_path.display(),
        log = %node_log_path.display(),
        node_bin = %node_bin.display(),
        "spawning PoC child process",
    );

    let child = tokio::process::Command::new(node_bin)
        .arg(process.role.as_str())
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_log))
        .spawn()?;

    Ok(RunningChild {
        role: process.role,
        instance_id: process.instance_id.clone(),
        node_log_path,
        progress_log_path,
        child,
    })
}

/// Formats the concise failure summary shown to operators when a child exits unexpectedly.
pub(crate) fn format_failure_summary(
    role: TransportRole,
    instance_id: &str,
    exit_code: Option<i32>,
    node_log_path: &Path,
    progress_log_path: &Path,
) -> String {
    let mut summary = String::new();
    let _ = write!(
        summary,
        "failure: {}:{} exited with code {:?}; inspect node log {} and progress log {}",
        role.as_str(),
        instance_id,
        exit_code,
        node_log_path.display(),
        progress_log_path.display()
    );
    summary
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use protocol_wire::control::TransportRole;

    use super::format_failure_summary;

    #[test]
    fn failure_summary_mentions_both_log_paths() {
        let summary = format_failure_summary(
            TransportRole::Wt,
            "wt",
            Some(7),
            Path::new("/tmp/node.log"),
            Path::new("/tmp/progress.log"),
        );

        assert!(summary.contains("/tmp/node.log"));
        assert!(summary.contains("/tmp/progress.log"));
    }
}
