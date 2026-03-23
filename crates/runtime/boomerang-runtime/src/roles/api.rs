use boomerang_config::{ProcessConfig, PublishedProcessIdentity};

use super::{factory, prelude::*};

pub trait RoleRuntime: Send {
    fn role(&self) -> TransportRole;
    fn accepted_tags(&self) -> &'static [MessageTag];
    fn published_identity(&self) -> Option<PublishedProcessIdentity> {
        None
    }

    fn on_start(&mut self) -> Result<Vec<OutboundFrame>, RuntimeError> {
        Ok(Vec::new())
    }

    fn handle_protocol_frame(
        &mut self,
        inbound: InboundFrame,
    ) -> Result<Vec<OutboundFrame>, RuntimeError>;

    fn run(&mut self, context: &mut RuntimeContext) -> Result<(), RuntimeError> {
        for outbound in self.on_start()? {
            context.send(&outbound)?;
        }

        loop {
            let inbound = match context.recv_any() {
                Ok(inbound) => inbound,
                Err(RuntimeError::InboundChannelClosed { .. }) => return Ok(()),
                Err(error) => return Err(error),
            };
            let outbound_frames = self.handle_protocol_frame(inbound)?;
            for outbound in outbound_frames {
                context.send(&outbound)?;
            }
        }
    }
}

pub fn build_role_runtime(config: &ProcessConfig) -> Result<Box<dyn RoleRuntime>, RuntimeError> {
    factory::build_role_runtime(config)
}
