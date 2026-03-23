use super::super::{api::RoleRuntime, prelude::*, shared::*, tags::*};

#[allow(dead_code)]
pub(crate) struct SarRuntime {
    pub(crate) instance_id: String,
    pub(crate) entity: Sar,
    pub(crate) peer_link: String,
    pub(crate) wt_link: String,
    pub(crate) sar_id: SarId,
}

impl RoleRuntime for SarRuntime {
    fn role(&self) -> TransportRole {
        TransportRole::Sar
    }

    fn accepted_tags(&self) -> &'static [MessageTag] {
        SAR_ACCEPTED_TAGS
    }

    fn published_identity(&self) -> Option<boomerang_config::PublishedProcessIdentity> {
        Some(boomerang_config::PublishedProcessIdentity::Sar {
            sar_id: self.sar_id.clone(),
        })
    }

    fn handle_protocol_frame(
        &mut self,
        inbound: InboundFrame,
    ) -> Result<Vec<OutboundFrame>, RuntimeError> {
        dispatch_not_implemented(self.role(), inbound)
    }

    fn run(&mut self, context: &mut RuntimeContext) -> Result<(), RuntimeError> {
        super::setup::run_setup(self, context)?;
        super::withdrawal::run_withdrawal(self, context)
    }
}
