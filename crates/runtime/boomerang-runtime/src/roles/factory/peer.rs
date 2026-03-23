use boomerang_config::ProcessConfig;

use super::super::{api::RoleRuntime, config::*, peer::runtime::PeerRuntime, prelude::*};
use crate::error::RuntimeError;

pub(super) fn build(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    let peer_bootstrap = peer_bootstrap_from_config(config)?;
    let peer_routes = peer_routes_from_config(config)?;
    Ok(Box::new(PeerRuntime {
        instance_id: config.instance_id.clone(),
        peer_index: peer_bootstrap.peer_index,
        total_peers: peer_bootstrap.total_peers,
        is_withdrawal_initiator: peer_bootstrap.is_withdrawal_initiator,
        assigned_sar_id: peer_bootstrap.assigned_sar_id,
        entity: peer_from_config(config)?,
        wt_link: peer_routes.wt_link,
        sar_link: peer_routes.sar_link,
        phone_link: peer_routes.phone_link,
        iso_link: peer_routes.iso_link,
        niso_link: peer_routes.niso_link,
        st_link: peer_routes.st_link,
        boomlet_link: peer_routes.boomlet_link,
        boomletwo_link: peer_routes.boomletwo_link,
        peer_links: peer_routes.peer_links,
        peer_id_to_link: BTreeMap::new(),
        link_to_peer_id: BTreeMap::new(),
        own_peer_id: None,
        own_wt_peer_id: None,
        own_boomerang_params: None,
        boomerang_config: config.boomerang.clone(),
        withdrawal_config: config.withdrawal.clone(),
        rpc_client_url: peer_bootstrap.rpc_client_url,
        rpc_client_auth: peer_bootstrap.rpc_client_auth,
    }))
}
