use super::super::{api::RoleRuntime, prelude::*, shared::dispatch_not_implemented, tags::*};

#[allow(dead_code)]
pub(crate) struct StRuntime {
    pub(crate) instance_id: String,
    pub(crate) entity: St,
    pub(crate) peer_link: String,
}

impl RoleRuntime for StRuntime {
    fn role(&self) -> TransportRole {
        TransportRole::St
    }

    fn accepted_tags(&self) -> &'static [MessageTag] {
        ST_ACCEPTED_TAGS
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
            "St handling inbound frame",
        );
        match tag {
            MessageTag::SetupIsoStMessage1
            | MessageTag::SetupIsoStMessage2
            | MessageTag::SetupIsoStMessage3
            | MessageTag::SetupNisoStMessage1
            | MessageTag::SetupNisoStMessage2
            | MessageTag::SetupStInput1
            | MessageTag::SetupStInput2
            | MessageTag::SetupStInput3 => super::setup::handle_setup_frame(self, inbound, tag),
            MessageTag::WithdrawalNisoStMessage1
            | MessageTag::WithdrawalNisoStMessage2
            | MessageTag::WithdrawalNisoStMessage3
            | MessageTag::WithdrawalNonInitiatorNisoNonInitiatorStMessage1
            | MessageTag::WithdrawalNonInitiatorNisoNonInitiatorStMessage2
            | MessageTag::WithdrawalStInput1
            | MessageTag::WithdrawalStInput2
            | MessageTag::WithdrawalStInput3
            | MessageTag::WithdrawalNonInitiatorStInput1
            | MessageTag::WithdrawalNonInitiatorStInput2 => {
                super::withdrawal::handle_withdrawal_frame(self, inbound, tag)
            }
            _ => dispatch_not_implemented(role, inbound),
        }
    }
}
