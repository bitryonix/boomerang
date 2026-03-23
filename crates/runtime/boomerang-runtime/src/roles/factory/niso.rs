use boomerang_config::ProcessConfig;

use super::super::{api::RoleRuntime, config::*, niso::runtime::NisoRuntime, prelude::*};
use crate::error::RuntimeError;

pub(super) fn build(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    let peer_link = single_peer_link(config, TransportRole::Niso)?;
    Ok(Box::new(NisoRuntime {
        instance_id: config.instance_id.clone(),
        entity: Niso::create_with_params(niso_params(&config.boomerang)),
        peer_link,
    }))
}
