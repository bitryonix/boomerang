use boomerang_config::ProcessConfig;

use super::super::{api::RoleRuntime, boomlet::BoomletRuntime, config::*, prelude::*};
use crate::error::RuntimeError;

pub(super) fn build(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    let peer_link = single_peer_link(config, TransportRole::Boomlet)?;
    Ok(Box::new(BoomletRuntime {
        instance_id: config.instance_id.clone(),
        slot: boomlet_slot_from_config(config)?,
        entity: boomlet_from_config(&config.boomerang),
        peer_link,
    }))
}
