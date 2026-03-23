//! Public launcher ports and compatibility entrypoints.

use std::{future::Future, path::Path, pin::Pin};

use boomerang_config::ClusterManifest;

use crate::error::RuntimeError;

/// Launches a validated cluster manifest using a concrete process host.
///
/// # Why this exists
/// The runtime crate should describe cluster-launch behavior without assuming that child
/// processes are always spawned through the local operating system.
pub type ClusterLaunchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'a>>;

pub trait ClusterLauncher: Send + Sync {
    /// Launches the requested cluster until it completes or one child fails.
    ///
    /// # Errors
    /// Returns a runtime error if the launcher cannot prepare per-process configs, cannot start
    /// the cluster, or observes a process failure during supervision.
    fn launch_cluster<'a>(
        &'a self,
        node_bin: &'a Path,
        manifest: &'a ClusterManifest,
    ) -> ClusterLaunchFuture<'a>;
}

/// Launches a cluster using an explicit launcher implementation.
///
/// # Why this exists
/// Tests and future hosts should be able to reuse the production launcher orchestration without
/// going through the fixed local-child-process path.
pub fn launch_cluster_with_launcher(
    node_bin: &Path,
    manifest: &ClusterManifest,
    launcher: &dyn ClusterLauncher,
) -> Result<(), RuntimeError> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| {
            handle.block_on(launch_cluster_async_with_launcher(
                node_bin, manifest, launcher,
            ))
        })
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(launch_cluster_async_with_launcher(
                node_bin, manifest, launcher,
            ))
    }
}

/// Launches a cluster using an explicit launcher implementation.
pub async fn launch_cluster_async_with_launcher(
    node_bin: &Path,
    manifest: &ClusterManifest,
    launcher: &dyn ClusterLauncher,
) -> Result<(), RuntimeError> {
    launcher.launch_cluster(node_bin, manifest).await
}
