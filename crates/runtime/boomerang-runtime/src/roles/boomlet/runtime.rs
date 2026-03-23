use super::super::{api::RoleRuntime, prelude::*, shared::dispatch_not_implemented, tags::*};

#[allow(dead_code)]
pub(crate) struct BoomletRuntime {
    pub(crate) instance_id: String,
    pub(crate) slot: BoomletSlot,
    pub(crate) entity: Boomlet,
    pub(crate) peer_link: String,
}

impl RoleRuntime for BoomletRuntime {
    fn role(&self) -> TransportRole {
        TransportRole::Boomlet
    }

    fn accepted_tags(&self) -> &'static [MessageTag] {
        BOOMLET_ACCEPTED_TAGS
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
            "Boomlet handling inbound frame",
        );
        match tag {
            MessageTag::SetupIsoBoomletMessage1
            | MessageTag::SetupIsoBoomletMessage2
            | MessageTag::SetupIsoBoomletMessage3
            | MessageTag::SetupIsoBoomletMessage4
            | MessageTag::SetupIsoBoomletMessage5
            | MessageTag::SetupIsoBoomletMessage6
            | MessageTag::SetupIsoBoomletwoMessage1
            | MessageTag::SetupIsoBoomletwoMessage2
            | MessageTag::SetupNisoBoomletMessage1
            | MessageTag::SetupNisoBoomletMessage2
            | MessageTag::SetupNisoBoomletMessage3
            | MessageTag::SetupNisoBoomletMessage4
            | MessageTag::SetupNisoBoomletMessage5
            | MessageTag::SetupNisoBoomletMessage6
            | MessageTag::SetupNisoBoomletMessage7
            | MessageTag::SetupNisoBoomletMessage8
            | MessageTag::SetupNisoBoomletMessage9
            | MessageTag::SetupNisoBoomletMessage10
            | MessageTag::SetupNisoBoomletMessage11
            | MessageTag::SetupNisoBoomletMessage12 => {
                super::setup::handle_setup_frame(self, inbound, tag)
            }
            MessageTag::WithdrawalNisoBoomletMessage1
            | MessageTag::WithdrawalNisoBoomletMessage2
            | MessageTag::WithdrawalNisoBoomletMessage3
            | MessageTag::WithdrawalNisoBoomletMessage4
            | MessageTag::WithdrawalNisoBoomletMessage5
            | MessageTag::WithdrawalNisoBoomletMessage6
            | MessageTag::WithdrawalNisoBoomletMessage7
            | MessageTag::WithdrawalNisoBoomletMessage8
            | MessageTag::WithdrawalNisoBoomletMessage9
            | MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1
            | MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2
            | MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3
            | MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4
            | MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5
            | MessageTag::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6
            | MessageTag::WithdrawalIsoBoomletMessage1
            | MessageTag::WithdrawalIsoBoomletMessage2 => {
                super::withdrawal::handle_withdrawal_frame(self, inbound, tag)
            }
            _ => dispatch_not_implemented(role, inbound),
        }
    }
}
