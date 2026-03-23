use super::runtime::WtRuntime;
use crate::roles::{api::RoleRuntime, prelude::*};

impl WtRuntime {
    pub(super) fn wt_peer_id_for_link(&self, link_name: &str) -> Result<WtPeerId, RuntimeError> {
        self.wt_peer_id_to_link
            .iter()
            .find_map(|(wt_peer_id, routed_link)| {
                (routed_link == link_name).then_some(wt_peer_id.clone())
            })
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role: self.role(),
                detail: format!("missing WT peer id mapping for link `{link_name}`"),
            })
    }

    pub(super) fn sar_id_for_link(&self, link_name: &str) -> Result<SarId, RuntimeError> {
        self.sar_id_to_link
            .iter()
            .find_map(|(sar_id, routed_link)| (routed_link == link_name).then_some(sar_id.clone()))
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role: self.role(),
                detail: format!("missing SAR id mapping for link `{link_name}`"),
            })
    }

    pub(super) fn initiator_peer_link(&self) -> Result<String, RuntimeError> {
        self.peer_links
            .get("peer-1")
            .cloned()
            .ok_or_else(|| RuntimeError::ProtocolStepFailed {
                role: self.role(),
                detail: "missing initiator peer route `peer-1`".to_owned(),
            })
    }
}
