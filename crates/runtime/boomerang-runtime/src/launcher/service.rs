//! Launcher helpers shared by concrete launcher implementations.

use std::path::PathBuf;

use boomerang_config::{ClusterManifest, ProcessConfig, save_process_config};

use crate::error::RuntimeError;

/// Returns the config path written for one spawned process.
pub(crate) fn config_path_for_process(process: &ProcessConfig) -> PathBuf {
    process.state_dir.join(format!(
        "{}-{}.toml",
        process.role.as_str(),
        process.instance_id
    ))
}

/// Returns the per-process log path used by the local child launcher.
pub(crate) fn log_path_for_process(process: &ProcessConfig) -> PathBuf {
    process.state_dir.join("node.log")
}

/// Writes one concrete process config file for every manifest entry.
pub fn write_cluster_process_configs(
    manifest: &ClusterManifest,
) -> Result<Vec<(ProcessConfig, PathBuf)>, RuntimeError> {
    manifest.validate()?;

    let mut written = Vec::with_capacity(manifest.processes.len());
    for process in &manifest.processes {
        let config_path = config_path_for_process(process);
        save_process_config(&config_path, process)?;
        written.push((process.clone(), config_path));
    }

    Ok(written)
}
