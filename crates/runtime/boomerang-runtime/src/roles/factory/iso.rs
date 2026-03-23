use boomerang_config::ProcessConfig;

use super::super::{api::RoleRuntime, config::*, iso::IsoRuntime, prelude::*};
use crate::error::RuntimeError;

pub(super) fn build(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    let peer_link = single_peer_link(config, TransportRole::Iso)?;
    Ok(Box::new(IsoRuntime {
        instance_id: config.instance_id.clone(),
        entity: Iso::create(),
        peer_link,
    }))
}
