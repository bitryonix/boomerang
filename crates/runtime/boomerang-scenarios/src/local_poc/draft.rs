//! Temporary draft models used while assembling the final cluster manifest.

use std::path::PathBuf;

use boomerang_config::{BoomerangNetworkConfig, ProcessBootstrap, WithdrawalConfig};
use boomerang_transport::LinkConfig;
use protocol_wire::control::TransportRole;

/// Partially-built process config used before routes are finalized.
#[derive(Debug, Clone)]
pub(super) struct ProcessDraft {
    pub(super) role: TransportRole,
    pub(super) instance_id: String,
    pub(super) state_dir: PathBuf,
    pub(super) bootstrap: ProcessBootstrap,
    pub(super) links: Vec<LinkConfig>,
    pub(super) boomerang: BoomerangNetworkConfig,
    pub(super) withdrawal: WithdrawalConfig,
}

/// Lightweight reference used when wiring bidirectional transport links.
#[derive(Clone, Copy)]
pub(super) struct ProcessRef<'a> {
    pub(super) role: TransportRole,
    pub(super) instance_id: &'a str,
}

/// Creates one borrowed process reference for link construction.
pub(super) fn process_ref<'a>(role: TransportRole, instance_id: &'a str) -> ProcessRef<'a> {
    ProcessRef { role, instance_id }
}
