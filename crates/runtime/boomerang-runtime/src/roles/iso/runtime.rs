use super::super::{api::RoleRuntime, prelude::*, shared::dispatch_not_implemented, tags::*};

#[allow(dead_code)]
pub(crate) struct IsoRuntime {
    pub(crate) instance_id: String,
    pub(crate) entity: Iso,
    pub(crate) peer_link: String,
}

impl RoleRuntime for IsoRuntime {
    fn role(&self) -> TransportRole {
        TransportRole::Iso
    }

    fn accepted_tags(&self) -> &'static [MessageTag] {
        ISO_ACCEPTED_TAGS
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
            "ISO handling inbound frame",
        );
        match tag {
            MessageTag::TransportResetState => {
                self.entity.reset_state();
                Ok(Vec::new())
            }
            MessageTag::SetupIsoInput1
            | MessageTag::SetupIsoInput2
            | MessageTag::SetupIsoInput3
            | MessageTag::SetupIsoInput4
            | MessageTag::SetupIsoInput5
            | MessageTag::SetupBoomletIsoMessage1
            | MessageTag::SetupBoomletIsoMessage2
            | MessageTag::SetupBoomletIsoMessage3
            | MessageTag::SetupBoomletIsoMessage4
            | MessageTag::SetupBoomletIsoMessage5
            | MessageTag::SetupBoomletIsoMessage6
            | MessageTag::SetupBoomletwoIsoMessage1
            | MessageTag::SetupBoomletwoIsoMessage2
            | MessageTag::SetupStIsoMessage1
            | MessageTag::SetupStIsoMessage2
            | MessageTag::SetupStIsoMessage3 => {
                super::setup::handle_setup_frame(self, inbound, tag)
            }
            MessageTag::WithdrawalIsoInput1
            | MessageTag::WithdrawalBoomletIsoMessage1
            | MessageTag::WithdrawalBoomletIsoMessage2 => {
                super::withdrawal::handle_withdrawal_frame(self, inbound, tag)
            }
            _ => dispatch_not_implemented(role, inbound),
        }
    }
}
