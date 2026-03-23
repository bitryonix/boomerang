use boomerang_config::ProcessConfig;

use super::super::{api::RoleRuntime, config::*, prelude::*, st::StRuntime};
use crate::error::RuntimeError;

pub(super) fn build(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    let peer_link = single_peer_link(config, TransportRole::St)?;
    Ok(Box::new(StRuntime {
        instance_id: config.instance_id.clone(),
        entity: St::create(),
        peer_link,
    }))
}
