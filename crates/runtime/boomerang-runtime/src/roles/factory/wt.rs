use boomerang_config::ProcessConfig;

use super::super::{api::RoleRuntime, config::*, prelude::*, wt::WtRuntime};
use crate::error::RuntimeError;

pub(super) fn build(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    let wt_routes = wt_routes_from_config(config)?;
    Ok(Box::new(WtRuntime {
        instance_id: config.instance_id.clone(),
        entity: wt_from_config(config)?,
        peer_links: wt_routes.peer_links,
        sar_links: wt_routes.sar_links,
        wt_peer_id_to_link: BTreeMap::new(),
        sar_id_to_link: BTreeMap::new(),
    }))
}
