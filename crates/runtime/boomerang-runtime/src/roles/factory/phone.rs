use boomerang_config::ProcessConfig;

use super::super::{api::RoleRuntime, config::*, phone::PhoneRuntime, prelude::*};
use crate::error::RuntimeError;

pub(super) fn build(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    let peer_link = single_peer_link(config, TransportRole::Phone)?;
    Ok(Box::new(PhoneRuntime {
        instance_id: config.instance_id.clone(),
        entity: Phone::create(),
        peer_link,
        assigned_sar_id: phone_sar_id_from_config(config)?,
    }))
}
