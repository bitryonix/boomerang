//! Cluster-launch façade and extension ports.

mod api;
mod local;
mod service;
#[cfg(test)]
mod tests;

use boomerang_config::ClusterManifest;
use std::path::Path;

use crate::error::RuntimeError;

pub use api::launch_cluster_async_with_launcher;
pub use api::{ClusterLauncher, launch_cluster_with_launcher};
pub use local::LocalChildLauncher;
pub use service::write_cluster_process_configs;

/// Launches a cluster with the supported local child-process launcher.
pub fn launch_cluster(node_bin: &Path, manifest: &ClusterManifest) -> Result<(), RuntimeError> {
    api::launch_cluster_with_launcher(node_bin, manifest, &LocalChildLauncher)
}

/// Launches a cluster with the supported async local child-process launcher.
pub async fn launch_cluster_async(
    node_bin: &Path,
    manifest: &ClusterManifest,
) -> Result<(), RuntimeError> {
    api::launch_cluster_async_with_launcher(node_bin, manifest, &LocalChildLauncher).await
}
