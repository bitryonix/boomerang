use super::super::{api::RoleRuntime, prelude::*, tags::*};

#[allow(dead_code)]
pub(crate) struct PhoneRuntime {
    pub(crate) instance_id: String,
    pub(crate) entity: Phone,
    pub(crate) peer_link: String,
    pub(crate) assigned_sar_id: SarId,
}

impl RoleRuntime for PhoneRuntime {
    fn role(&self) -> TransportRole {
        TransportRole::Phone
    }

    fn accepted_tags(&self) -> &'static [MessageTag] {
        PHONE_ACCEPTED_TAGS
    }

    fn handle_protocol_frame(
        &mut self,
        inbound: InboundFrame,
    ) -> Result<Vec<OutboundFrame>, RuntimeError> {
        let tag = inbound.frame.message_tag()?;
        debug!(
            instance_id = %self.instance_id,
            link_name = %inbound.link_name,
            ?tag,
            "Phone handling inbound frame",
        );

        super::setup::handle_setup_frame(self, inbound)
    }
}
