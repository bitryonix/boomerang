//! Small runtime-only structs derived from manifest data.

use std::collections::BTreeMap;

use protocol::constructs::SarId;

/// Peer bootstrap values extracted from a process manifest.
#[derive(Clone)]
pub(crate) struct PeerBootstrapRuntime {
    pub(crate) peer_index: usize,
    pub(crate) total_peers: usize,
    pub(crate) is_withdrawal_initiator: bool,
    pub(crate) assigned_sar_id: SarId,
    pub(crate) rpc_client_url: std::net::SocketAddrV4,
    pub(crate) rpc_client_auth: protocol::constructs::BitcoinCoreAuth,
}

/// WT route names extracted from a process manifest.
#[derive(Clone)]
pub(crate) struct WtRoutesRuntime {
    pub(crate) peer_links: BTreeMap<String, String>,
    pub(crate) sar_links: BTreeMap<String, String>,
}

/// Peer route names extracted from a process manifest.
#[derive(Clone)]
pub(crate) struct PeerRoutesRuntime {
    pub(crate) wt_link: String,
    pub(crate) sar_link: String,
    pub(crate) phone_link: String,
    pub(crate) iso_link: String,
    pub(crate) niso_link: String,
    pub(crate) st_link: String,
    pub(crate) boomlet_link: String,
    pub(crate) boomletwo_link: String,
    pub(crate) peer_links: BTreeMap<String, String>,
}
