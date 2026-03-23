//! Role-construction façade for runtime bootstrap.

mod boomlet;
mod iso;
mod niso;
mod peer;
mod phone;
mod sar;
mod st;
mod wt;

use boomerang_config::ProcessConfig;

use super::{api::RoleRuntime, prelude::*};
use crate::error::RuntimeError;

/// Builds the concrete role runtime for one validated process config.
pub(crate) fn build_role_runtime(
    config: &ProcessConfig,
) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    match config.role {
        TransportRole::Wt => wt::build(config),
        TransportRole::Sar => sar::build(config),
        TransportRole::Peer => peer::build(config),
        TransportRole::Niso => niso::build(config),
        TransportRole::Iso => iso::build(config),
        TransportRole::Boomlet => boomlet::build(config),
        TransportRole::Phone => phone::build(config),
        TransportRole::St => st::build(config),
    }
}
