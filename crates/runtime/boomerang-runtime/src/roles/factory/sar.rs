use boomerang_config::ProcessConfig;

use super::super::{api::RoleRuntime, config::*, sar::SarRuntime};
use crate::error::RuntimeError;

pub(super) fn build(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    let (peer_link, wt_link) = sar_routes_from_config(config)?;
    let entity = sar_from_config(config)?;
    let sar_id = entity
        .get_sar_id()
        .ok_or_else(|| RuntimeError::InvalidBootstrap {
            role: config.role,
            reason: "SAR initialization did not publish a SAR id".to_owned(),
        })?;
    Ok(Box::new(SarRuntime {
        instance_id: config.instance_id.clone(),
        entity,
        peer_link,
        wt_link,
        sar_id,
    }))
}
