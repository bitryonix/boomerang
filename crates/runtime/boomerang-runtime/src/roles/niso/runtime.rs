use super::super::{
    api::RoleRuntime,
    prelude::*,
    shared::{dispatch_not_implemented, single_outbound},
    tags::*,
};

#[allow(dead_code)]
pub(crate) struct NisoRuntime {
    pub(crate) instance_id: String,
    pub(crate) entity: Niso,
    pub(crate) peer_link: String,
}

impl RoleRuntime for NisoRuntime {
    fn role(&self) -> TransportRole {
        TransportRole::Niso
    }

    fn accepted_tags(&self) -> &'static [MessageTag] {
        NISO_ACCEPTED_TAGS
    }

    fn handle_protocol_frame(
        &mut self,
        inbound: InboundFrame,
    ) -> Result<Vec<OutboundFrame>, RuntimeError> {
        let role = self.role();
        let tag = inbound.frame.message_tag()?;
        debug!(
            instance_id = %self.instance_id,
            link_name = %inbound.link_name,
            ?tag,
            "NISO handling inbound frame",
        );

        match tag {
            MessageTag::QueryNisoState => {
                let snapshot = NisoStateSnapshot::new(
                    self.entity.get_peer_id(),
                    self.entity.get_wt_peer_id(),
                    self.entity.get_boomerang_params(),
                );
                single_outbound(self.peer_link.clone(), &snapshot)
            }
            _ if is_niso_setup_tag(tag) => self.handle_setup_frame(inbound),
            _ if is_niso_withdrawal_tag(tag) => self.handle_withdrawal_frame(inbound),
            _ => dispatch_not_implemented(role, inbound),
        }
    }
}

fn is_niso_setup_tag(tag: MessageTag) -> bool {
    // The peer-to-peer NISO parcel wrappers moved into the wire-control namespace during the
    // protocol-wire extraction, so they no longer fall inside the raw setup range even though
    // they still belong to the setup workflow.
    matches!(
        tag,
        MessageTag::SetupNisoPeerNisoParcel1
            | MessageTag::SetupNisoPeerNisoParcel2
            | MessageTag::SetupNisoPeerNisoParcel3
            | MessageTag::SetupNisoPeerNisoParcel4
    ) || matches!(tag.as_u16(), 0x1000..=0x1fff)
}

fn is_niso_withdrawal_tag(tag: MessageTag) -> bool {
    matches!(tag.as_u16(), 0x2000..=0x2fff)
}

#[cfg(test)]
mod tests {
    use super::{is_niso_setup_tag, is_niso_withdrawal_tag};
    use crate::roles::prelude::MessageTag;

    #[test]
    fn treats_peer_niso_parcels_as_setup_tags() {
        assert!(is_niso_setup_tag(MessageTag::SetupNisoPeerNisoParcel1));
        assert!(is_niso_setup_tag(MessageTag::SetupNisoPeerNisoParcel2));
        assert!(is_niso_setup_tag(MessageTag::SetupNisoPeerNisoParcel3));
        assert!(is_niso_setup_tag(MessageTag::SetupNisoPeerNisoParcel4));
    }

    #[test]
    fn keeps_withdrawal_tags_separate_from_setup_tags() {
        assert!(is_niso_withdrawal_tag(MessageTag::WithdrawalNisoInput1));
        assert!(!is_niso_setup_tag(MessageTag::WithdrawalNisoInput1));
    }
}
