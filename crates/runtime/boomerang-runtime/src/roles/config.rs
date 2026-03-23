//! Bootstrap and route extraction helpers for role runtime construction.

mod bootstrap;
mod routes;
mod runtime_types;
#[cfg(test)]
mod tests;

pub(crate) use bootstrap::{
    boomlet_from_config, boomlet_slot_from_config, niso_params, peer_bootstrap_from_config,
    peer_from_config, phone_sar_id_from_config, sar_from_config, wt_from_config,
};
pub(crate) use routes::{
    peer_routes_from_config, sar_routes_from_config, single_peer_link, wt_routes_from_config,
};
