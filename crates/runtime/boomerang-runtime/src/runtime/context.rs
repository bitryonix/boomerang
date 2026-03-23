//! Shared runtime context used by role implementations.

use std::collections::{BTreeMap, VecDeque};

use boomerang_transport::{
    InboundFrame, LinkWriters, OutboundFrame, TcpTransportSession, TransportError, TransportSession,
};
use protocol_wire::{MessageTag, WireMessage};

use crate::error::RuntimeError;

/// Shared I/O context used by every role runtime.
pub struct RuntimeContext {
    role: protocol_wire::control::TransportRole,
    accepted_tags: &'static [MessageTag],
    session: Box<dyn TransportSession>,
    pending_by_link: BTreeMap<String, VecDeque<InboundFrame>>,
    progress_path: std::path::PathBuf,
}

impl RuntimeContext {
    /// Creates one runtime context for a fully-established role process.
    pub fn new(
        role: protocol_wire::control::TransportRole,
        accepted_tags: &'static [MessageTag],
        inbound_rx: tokio::sync::mpsc::Receiver<InboundFrame>,
        writers: LinkWriters,
        progress_path: std::path::PathBuf,
    ) -> Self {
        Self::with_transport_session(
            role,
            accepted_tags,
            Box::new(TcpTransportSession::new(inbound_rx, writers)),
            progress_path,
        )
    }

    /// Creates one runtime context from a generic transport session.
    pub fn with_transport_session(
        role: protocol_wire::control::TransportRole,
        accepted_tags: &'static [MessageTag],
        session: Box<dyn TransportSession>,
        progress_path: std::path::PathBuf,
    ) -> Self {
        Self {
            role,
            accepted_tags,
            session,
            pending_by_link: BTreeMap::new(),
            progress_path,
        }
    }

    /// Sends one already-encoded outbound frame.
    pub fn send(&self, outbound: &OutboundFrame) -> Result<(), RuntimeError> {
        Ok(self.session.send(outbound, self.role)?)
    }

    /// Encodes and sends one typed message on the named link.
    pub fn send_message<M: WireMessage>(
        &self,
        link_name: impl Into<String>,
        message: &M,
    ) -> Result<(), RuntimeError> {
        self.send(&OutboundFrame::from_message(link_name, message)?)
    }

    /// Receives the next available inbound frame on any accepted link.
    pub fn recv_any(&mut self) -> Result<InboundFrame, RuntimeError> {
        if let Some(link_name) = self
            .pending_by_link
            .iter()
            .find_map(|(link_name, queue)| (!queue.is_empty()).then_some(link_name.clone()))
        {
            let queue = self.pending_by_link.get_mut(&link_name).ok_or_else(|| {
                RuntimeError::PendingQueueInvariantViolated {
                    role: self.role,
                    link_name: link_name.clone(),
                }
            })?;

            // The selection pass only chooses non-empty queues, so an empty queue here means the
            // runtime's in-memory ordering state drifted and should fail loudly.
            return queue
                .pop_front()
                .ok_or(RuntimeError::PendingQueueInvariantViolated {
                    role: self.role,
                    link_name,
                });
        }

        self.recv_from_transport()
    }

    /// Receives the next inbound frame for one specific link, buffering other links in memory.
    pub fn recv_on(&mut self, link_name: &str) -> Result<InboundFrame, RuntimeError> {
        if let Some(queue) = self.pending_by_link.get_mut(link_name) {
            if let Some(inbound) = queue.pop_front() {
                return Ok(inbound);
            }
        }

        loop {
            let inbound = self.recv_from_transport()?;
            if inbound.link_name == link_name {
                return Ok(inbound);
            }

            // Frames for other links are buffered so role code can block on one conversation
            // without reordering or dropping concurrent traffic from other peers.
            self.pending_by_link
                .entry(inbound.link_name.clone())
                .or_default()
                .push_back(inbound);
        }
    }

    /// Receives and decodes the next typed message for one specific link.
    pub fn recv_message<M: WireMessage>(&mut self, link_name: &str) -> Result<M, RuntimeError> {
        let inbound = self.recv_on(link_name)?;
        super::codec::decode_frame::<M>(&inbound.frame)
    }

    /// Appends one progress line to this process's progress log.
    pub fn record_progress(&self, line: &str) -> Result<(), RuntimeError> {
        super::progress::append_progress_line(&self.progress_path, line)
    }

    /// Flushes and tears down the transport session after the role workflow returns.
    pub fn shutdown(self, runtime_handle: &tokio::runtime::Handle) -> Result<(), RuntimeError> {
        self.session
            .shutdown(runtime_handle)
            .map_err(RuntimeError::from)
    }

    /// Receives the next frame from the active transport session and enforces tag allow-lists.
    fn recv_from_transport(&mut self) -> Result<InboundFrame, RuntimeError> {
        let inbound = match self.session.recv() {
            Ok(inbound) => inbound,
            Err(TransportError::InboundChannelClosed) => {
                return Err(RuntimeError::InboundChannelClosed { role: self.role });
            }
            Err(error) => return Err(error.into()),
        };
        let tag = inbound.frame.message_tag()?;
        if !self.accepted_tags.contains(&tag) {
            return Err(RuntimeError::UnexpectedProtocolTag {
                role: self.role,
                link_name: inbound.link_name,
                tag,
            });
        }

        Ok(inbound)
    }

    #[cfg(test)]
    pub(crate) fn push_pending_for_test(&mut self, inbound: InboundFrame) {
        self.pending_by_link
            .entry(inbound.link_name.clone())
            .or_default()
            .push_back(inbound);
    }
}
