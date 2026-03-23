//! Route extraction helpers driven by `ProcessRoutes`.

use super::super::prelude::*;
use super::runtime_types::{PeerRoutesRuntime, WtRoutesRuntime};

pub(crate) fn wt_routes_from_config(
    config: &ProcessConfig,
) -> Result<WtRoutesRuntime, RuntimeError> {
    let ProcessRoutes::Wt {
        peer_links,
        sar_links,
    } = &config.routes
    else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Wt,
            reason: "missing WT routes payload".to_owned(),
        });
    };

    Ok(WtRoutesRuntime {
        peer_links: peer_links.clone(),
        sar_links: sar_links.clone(),
    })
}

pub(crate) fn sar_routes_from_config(
    config: &ProcessConfig,
) -> Result<(String, String), RuntimeError> {
    let ProcessRoutes::Sar { peer_link, wt_link } = &config.routes else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Sar,
            reason: "missing SAR routes payload".to_owned(),
        });
    };

    Ok((peer_link.clone(), wt_link.clone()))
}

pub(crate) fn peer_routes_from_config(
    config: &ProcessConfig,
) -> Result<PeerRoutesRuntime, RuntimeError> {
    let ProcessRoutes::Peer {
        wt_link,
        sar_link,
        phone_link,
        iso_link,
        niso_link,
        st_link,
        boomlet_link,
        boomletwo_link,
        peer_links,
    } = &config.routes
    else {
        return Err(RuntimeError::InvalidBootstrap {
            role: TransportRole::Peer,
            reason: "missing Peer routes payload".to_owned(),
        });
    };

    Ok(PeerRoutesRuntime {
        wt_link: wt_link.clone(),
        sar_link: sar_link.clone(),
        phone_link: phone_link.clone(),
        iso_link: iso_link.clone(),
        niso_link: niso_link.clone(),
        st_link: st_link.clone(),
        boomlet_link: boomlet_link.clone(),
        boomletwo_link: boomletwo_link.clone(),
        peer_links: peer_links.clone(),
    })
}

pub(crate) fn single_peer_link(
    config: &ProcessConfig,
    role: TransportRole,
) -> Result<String, RuntimeError> {
    match (&config.routes, role) {
        (ProcessRoutes::Niso { peer_link }, TransportRole::Niso)
        | (ProcessRoutes::Iso { peer_link }, TransportRole::Iso)
        | (ProcessRoutes::Boomlet { peer_link }, TransportRole::Boomlet)
        | (ProcessRoutes::Phone { peer_link }, TransportRole::Phone)
        | (ProcessRoutes::St { peer_link }, TransportRole::St) => Ok(peer_link.clone()),
        _ => Err(RuntimeError::InvalidBootstrap {
            role,
            reason: "missing single-peer route payload".to_owned(),
        }),
    }
}
