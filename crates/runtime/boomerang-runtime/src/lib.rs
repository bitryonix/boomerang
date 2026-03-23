#![forbid(unsafe_code)]

pub mod error;
pub mod launcher;
pub mod roles;
pub mod runtime;

pub use error::RuntimeError;
pub use launcher::{
    ClusterLauncher, LocalChildLauncher, launch_cluster, launch_cluster_async,
    launch_cluster_async_with_launcher, launch_cluster_with_launcher,
};
pub use roles::{RoleRuntime, build_role_runtime};
pub use runtime::{
    run_process, run_process_async, run_process_async_with_transport, run_process_with_transport,
};
