//! TCP-backed implementations of the generic transport ports.

use std::{path::Path, sync::Arc};

use protocol_wire::control::TransportRole;

use crate::{
    delay::{LinkDelayPolicy, NoDelayLinkDelayPolicy},
    error::TransportError,
    interface::{TransportInterface, TransportSession, TransportSessionFuture},
    transport::{
        EstablishedLinks, InboundFrame, LinkConfig, LinkWriters, LocalProcessIdentity,
        OutboundFrame, establish_links_with_delay, write_outbound_frame,
    },
};

/// Default transport backend used by the supported runtime path.
///
/// # Why this exists
/// The runtime crate needs a concrete `TransportInterface` it can depend on for the current TCP
/// deployment while still leaving room for future backends.
#[derive(Clone)]
pub struct TcpTransportInterface {
    delay_policy: Arc<dyn LinkDelayPolicy>,
}

impl std::fmt::Debug for TcpTransportInterface {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpTransportInterface")
            .field("delay_policy", &"dyn LinkDelayPolicy")
            .finish()
    }
}

impl Default for TcpTransportInterface {
    fn default() -> Self {
        Self {
            delay_policy: Arc::new(NoDelayLinkDelayPolicy),
        }
    }
}

impl TcpTransportInterface {
    /// Creates the TCP transport backend with an explicit delay policy.
    pub fn new(delay_policy: Arc<dyn LinkDelayPolicy>) -> Self {
        Self { delay_policy }
    }
}

impl TransportInterface for TcpTransportInterface {
    fn establish_session<'a>(
        &'a self,
        local: &'a LocalProcessIdentity,
        links: &'a [LinkConfig],
        progress_path: &'a Path,
    ) -> TransportSessionFuture<'a, Result<Box<dyn TransportSession>, TransportError>> {
        Box::pin(async move {
            let established = establish_links_with_delay(
                local,
                links,
                progress_path,
                Arc::clone(&self.delay_policy),
            )
            .await?;
            Ok::<Box<dyn TransportSession>, TransportError>(Box::new(
                TcpTransportSession::from_established(established),
            ))
        })
    }
}

/// Runtime-facing session backed by TCP reader threads and synchronized writers.
///
/// # Why this exists
/// The current TCP backend uses a channel-fed reader side plus one writer mutex per link. This
/// type packages that internal layout behind the backend-neutral [`TransportSession`] trait.
pub struct TcpTransportSession {
    inbound_rx: Option<tokio::sync::mpsc::Receiver<InboundFrame>>,
    writers: Option<LinkWriters>,
    task_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl TcpTransportSession {
    /// Creates one TCP session from already-established readers and writers.
    ///
    /// # Why this exists
    /// Tests and compatibility wrappers sometimes establish links first and only later decide to
    /// wrap them in the generic session API.
    pub fn from_established(established: EstablishedLinks) -> Self {
        Self {
            inbound_rx: Some(established.inbound_rx),
            writers: Some(established.writers),
            task_handles: established.task_handles,
        }
    }

    /// Creates one TCP session from explicit writers and a prebuilt inbound receiver.
    ///
    /// # Why this exists
    /// Tests for runtime buffering and compatibility wrappers need a way to assemble a session
    /// without creating real sockets.
    pub fn new(
        inbound_rx: tokio::sync::mpsc::Receiver<InboundFrame>,
        writers: LinkWriters,
    ) -> Self {
        Self {
            inbound_rx: Some(inbound_rx),
            writers: Some(writers),
            task_handles: Vec::new(),
        }
    }
}

impl TransportSession for TcpTransportSession {
    fn send(
        &self,
        outbound: &OutboundFrame,
        local_role: TransportRole,
    ) -> Result<(), TransportError> {
        let writers =
            self.writers
                .as_ref()
                .ok_or_else(|| TransportError::OutboundChannelClosed {
                    link_name: outbound.link_name.clone(),
                })?;
        write_outbound_frame(writers, outbound, local_role)
    }

    fn recv(&mut self) -> Result<InboundFrame, TransportError> {
        self.inbound_rx
            .as_mut()
            .ok_or(TransportError::InboundChannelClosed)?
            .blocking_recv()
            .ok_or(TransportError::InboundChannelClosed)
    }

    fn shutdown(
        mut self: Box<Self>,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Result<(), TransportError> {
        drop(self.inbound_rx.take());
        drop(self.writers.take());
        let task_handles = std::mem::take(&mut self.task_handles);

        runtime_handle.block_on(async move {
            for handle in task_handles {
                match handle.await {
                    Ok(()) => {}
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        return Err(TransportError::BackgroundTaskFailed {
                            detail: error.to_string(),
                        });
                    }
                }
            }

            Ok(())
        })
    }
}

impl Drop for TcpTransportSession {
    fn drop(&mut self) {
        for handle in &self.task_handles {
            handle.abort();
        }
    }
}
