//! Unit tests for launcher ports and helpers.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use boomerang_config::ClusterManifest;

use super::{
    api::{ClusterLaunchFuture, ClusterLauncher, launch_cluster_with_launcher},
    service::write_cluster_process_configs,
};

struct RecordingLauncher {
    calls: Arc<Mutex<Vec<(PathBuf, usize)>>>,
}

impl ClusterLauncher for RecordingLauncher {
    fn launch_cluster<'a>(
        &'a self,
        node_bin: &'a Path,
        manifest: &'a ClusterManifest,
    ) -> ClusterLaunchFuture<'a> {
        Box::pin(async move {
            self.calls
                .lock()
                .expect("recording launcher mutex should not be poisoned")
                .push((node_bin.to_path_buf(), manifest.processes.len()));
            Ok(())
        })
    }
}

#[test]
fn launch_cluster_with_launcher_uses_supplied_launcher() {
    let manifest = ClusterManifest {
        processes: Vec::new(),
    };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let launcher = RecordingLauncher {
        calls: Arc::clone(&calls),
    };

    launch_cluster_with_launcher(Path::new("/tmp/boomerang-node"), &manifest, &launcher)
        .expect("recording launcher should succeed");

    let recorded = calls
        .lock()
        .expect("recording launcher mutex should not be poisoned");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, PathBuf::from("/tmp/boomerang-node"));
    assert_eq!(recorded[0].1, 0);
}

#[test]
fn write_cluster_process_configs_accepts_empty_manifest() {
    let manifest = ClusterManifest {
        processes: Vec::new(),
    };
    let written = write_cluster_process_configs(&manifest)
        .expect("empty manifests should still validate and write nothing");
    assert!(written.is_empty());
}
