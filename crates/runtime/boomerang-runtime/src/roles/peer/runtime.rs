use super::super::{api::RoleRuntime, prelude::*, shared::dispatch_not_implemented, tags::*};

#[allow(dead_code)]
pub(crate) struct PeerRuntime {
    pub(crate) instance_id: String,
    pub(crate) peer_index: usize,
    pub(crate) total_peers: usize,
    pub(crate) is_withdrawal_initiator: bool,
    pub(crate) assigned_sar_id: SarId,
    pub(crate) entity: Peer,
    pub(crate) wt_link: String,
    pub(crate) sar_link: String,
    pub(crate) phone_link: String,
    pub(crate) iso_link: String,
    pub(crate) niso_link: String,
    pub(crate) st_link: String,
    pub(crate) boomlet_link: String,
    pub(crate) boomletwo_link: String,
    pub(crate) peer_links: BTreeMap<String, String>,
    pub(crate) peer_id_to_link: BTreeMap<PeerId, String>,
    pub(crate) link_to_peer_id: BTreeMap<String, PeerId>,
    pub(crate) own_peer_id: Option<PeerId>,
    pub(crate) own_wt_peer_id: Option<WtPeerId>,
    pub(crate) own_boomerang_params: Option<BoomerangParams>,
    pub(crate) boomerang_config: BoomerangNetworkConfig,
    pub(crate) withdrawal_config: WithdrawalConfig,
    pub(crate) rpc_client_url: std::net::SocketAddrV4,
    pub(crate) rpc_client_auth: BitcoinCoreAuth,
}

impl RoleRuntime for PeerRuntime {
    fn role(&self) -> TransportRole {
        TransportRole::Peer
    }

    fn accepted_tags(&self) -> &'static [MessageTag] {
        PEER_ACCEPTED_TAGS
    }

    fn handle_protocol_frame(
        &mut self,
        inbound: InboundFrame,
    ) -> Result<Vec<OutboundFrame>, RuntimeError> {
        dispatch_not_implemented(self.role(), inbound)
    }

    fn run(&mut self, context: &mut RuntimeContext) -> Result<(), RuntimeError> {
        self.run_setup(context)?;
        self.run_withdrawal(context)
    }
}
