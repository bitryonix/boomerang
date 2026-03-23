//! Backend-neutral transport interfaces for runtime composition.
//!
//! # Why this exists
//! The workspace currently runs every process over blocking TCP, but future interfaces may want
//! to reuse the same runtime orchestration with a different transport backend. Keeping these ports
//! in their own module lets `boomerang-runtime` depend on a stable abstraction instead of on one
//! concrete socket implementation.
//!
//! # Role in the system
//! [`TransportInterface`] establishes one runtime-facing session for a process, while
//! [`TransportSession`] is the backend-neutral send/receive surface that `boomerang-runtime` uses
//! after startup.

use std::{future::Future, path::Path, pin::Pin};

use protocol_wire::control::TransportRole;

use crate::{
    error::TransportError,
    transport::{InboundFrame, LinkConfig, LocalProcessIdentity, OutboundFrame},
};

/// Heap-allocated future returned by transport establishment APIs.
pub type TransportSessionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Establishes a concrete transport session for one configured process.
///
/// # Why this exists
/// Runtime startup should be able to ask for "a transport session" without caring whether that
/// session came from TCP, a test double, or a future embedded interface.
///
/// # Role in the system
/// The runtime crate uses this trait to create the session that later feeds frames into a
/// [`TransportSession`].
pub trait TransportInterface: Send + Sync {
    /// Creates a fully initialized transport session for one local process identity and link set.
    ///
    /// # Why this exists
    /// Session establishment is the boundary where manifests, transport-specific startup, and
    /// operational progress logging meet.
    ///
    /// # Errors
    /// Returns a transport error if link validation fails, the backend cannot initialize, or the
    /// backend cannot produce a usable runtime session.
    fn establish_session<'a>(
        &'a self,
        local: &'a LocalProcessIdentity,
        links: &'a [LinkConfig],
        progress_path: &'a Path,
    ) -> TransportSessionFuture<'a, Result<Box<dyn TransportSession>, TransportError>>;
}

/// Backend-neutral framed send/receive surface used by the runtime layer.
///
/// # Why this exists
/// Role runtimes already consume `InboundFrame` and produce `OutboundFrame`. This trait keeps that
/// interaction stable even when the concrete transport backend changes.
///
/// # Role in the system
/// Owned by the runtime layer after process bootstrap succeeds.
pub trait TransportSession: Send {
    /// Sends one already-routed outbound frame.
    ///
    /// # Why this exists
    /// The runtime should address links by their manifest names and let the transport backend
    /// decide how that frame reaches the peer.
    ///
    /// # Errors
    /// Returns a transport error when the route is unknown, the backend writer is unavailable, or
    /// the frame cannot be delivered.
    fn send(
        &self,
        outbound: &OutboundFrame,
        local_role: TransportRole,
    ) -> Result<(), TransportError>;

    /// Blocks until the next inbound frame arrives or the session shuts down.
    ///
    /// # Why this exists
    /// Runtime dispatch needs one blocking receive primitive that is independent of the concrete
    /// backend's threading model.
    ///
    /// # Errors
    /// Returns a transport error if the session fails or if the receive side has shut down.
    fn recv(&mut self) -> Result<InboundFrame, TransportError>;

    /// Flushes and tears down the session's background transport work.
    ///
    /// # Why this exists
    /// Role runtimes often send their final outbound frames immediately before returning. The
    /// transport layer must therefore finish draining queued writes before the process exits, or
    /// the peer may never observe those last messages.
    ///
    /// # Errors
    /// Returns a transport error if a background writer or reader task fails while the session is
    /// shutting down.
    fn shutdown(
        self: Box<Self>,
        runtime_handle: &tokio::runtime::Handle,
    ) -> Result<(), TransportError>;
}
