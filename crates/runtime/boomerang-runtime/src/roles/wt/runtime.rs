use super::super::{api::RoleRuntime, prelude::*, shared::dispatch_not_implemented, tags::*};

#[allow(dead_code)]
pub(crate) struct WtRuntime {
    pub(crate) instance_id: String,
    pub(crate) entity: Wt,
    pub(crate) peer_links: BTreeMap<String, String>,
    pub(crate) sar_links: BTreeMap<String, String>,
    pub(crate) wt_peer_id_to_link: BTreeMap<WtPeerId, String>,
    pub(crate) sar_id_to_link: BTreeMap<SarId, String>,
}

impl RoleRuntime for WtRuntime {
    fn role(&self) -> TransportRole {
        TransportRole::Wt
    }

    fn accepted_tags(&self) -> &'static [MessageTag] {
        WT_ACCEPTED_TAGS
    }

    fn published_identity(&self) -> Option<boomerang_config::PublishedProcessIdentity> {
        self.entity
            .get_wt_id()
            .map(|wt_id| boomerang_config::PublishedProcessIdentity::Wt { wt_id })
    }

    fn handle_protocol_frame(
        &mut self,
        inbound: InboundFrame,
    ) -> Result<Vec<OutboundFrame>, RuntimeError> {
        dispatch_not_implemented(self.role(), inbound)
    }

    fn run(&mut self, context: &mut RuntimeContext) -> Result<(), RuntimeError> {
        let peer_link_names = self.peer_links.values().cloned().collect::<Vec<_>>();
        let sar_link_names = self.sar_links.values().cloned().collect::<Vec<_>>();
        let peer_instance_by_link = self
            .peer_links
            .iter()
            .map(|(instance_id, link_name)| (link_name.clone(), instance_id.clone()))
            .collect::<BTreeMap<_, _>>();
        super::setup::run_setup(
            self,
            context,
            &peer_link_names,
            &sar_link_names,
            &peer_instance_by_link,
        )?;
        super::withdrawal::run_withdrawal(self, context, &peer_link_names, &sar_link_names)
    }
}
