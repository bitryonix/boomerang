//! Transport-facing data models.
//!
//! # Why this exists
//! Link metadata, framed envelopes, and established socket collections are core transport concepts
//! with stable meaning independent of handshake or socket I/O details.
//!
//! # Role in the system
//! These types are shared by the handshake, frame I/O, and orchestration modules inside the crate.

use std::{collections::BTreeMap, net::SocketAddr};

use protocol_wire::{ProtocolFrame, WireMessage, control::TransportRole};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, task::JoinHandle};

use crate::error::TransportError;

/// Identifies the currently running process on the transport layer.
///
/// # Why this exists
/// Every TCP link handshake needs a stable local role and instance id so peers can reject
/// miswired connections before domain traffic starts flowing.
///
/// # Role in the system
/// Runtime bootstrap passes this value into handshake and link-establishment logic.
///
/// # Examples
/// A WT process uses this during startup so peers can verify they connected to the intended node:
///
/// ```text
/// let local = LocalProcessIdentity::new(TransportRole::Wt, "wt-1");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProcessIdentity {
    /// Role the current process is expected to play on every configured link.
    pub role: TransportRole,
    /// Stable process instance id used to reject accidental cross-wiring.
    pub instance_id: String,
}

impl LocalProcessIdentity {
    /// Creates the local transport identity used for link handshakes.
    ///
    /// # Why this exists
    /// Most callers already know their role and instance id at bootstrap time, so a lightweight
    /// constructor keeps that intent explicit instead of assembling the struct field-by-field.
    ///
    /// # Role in the system
    /// Used by runtime startup before any sockets are opened.
    ///
    /// # Examples
    /// A peer process prepares its identity before establishing links:
    ///
    /// ```text
    /// let local = LocalProcessIdentity::new(TransportRole::Peer, "peer-3");
    /// ```
    pub fn new(role: TransportRole, instance_id: impl Into<String>) -> Self {
        Self {
            role,
            instance_id: instance_id.into(),
        }
    }
}

/// Describes one transport link between the local process and one expected remote process.
///
/// # Why this exists
/// Startup configuration needs a transport-specific model that captures both addressing mode and
/// expected peer identity while remaining independent of runtime role orchestration.
///
/// # Role in the system
/// Process manifests deserialize into this type before link validation and socket establishment.
///
/// # Examples
/// A peer process may connect outward to the WT while the WT binds and accepts:
///
/// ```text
/// LinkConfig {
///     name: "wt-peer-1".to_owned(),
///     peer_role: TransportRole::Wt,
///     peer_instance_id: "wt-1".to_owned(),
///     bind_addr: None,
///     connect_addr: Some("127.0.0.1:24001".parse()?),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkConfig {
    /// Human-readable link name used by manifests, logs, and route selection.
    pub name: String,
    /// Role the remote process must present during the transport handshake.
    pub peer_role: TransportRole,
    /// Stable remote instance id expected on this link.
    pub peer_instance_id: String,
    /// Local listener address when the current process accepts inbound TCP for this link.
    pub bind_addr: Option<SocketAddr>,
    /// Remote address when the current process actively connects for this link.
    pub connect_addr: Option<SocketAddr>,
}

impl LinkConfig {
    /// Validates the basic invariants for one transport link definition.
    ///
    /// # Why this exists
    /// The transport layer must fail fast on malformed manifests so callers do not reach a partial
    /// startup state with missing listeners or ambiguous socket modes.
    ///
    /// # Role in the system
    /// Called before sockets are opened by [`crate::establish_links`].
    ///
    /// # Errors
    /// Returns [`TransportError::InvalidLinkConfig`] when the name is empty, the peer instance id
    /// is empty, or the link does not choose exactly one of bind or connect mode.
    ///
    /// # Examples
    /// The runtime validates every manifest link before network I/O begins:
    ///
    /// ```text
    /// link.validate()?;
    /// ```
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.name.trim().is_empty() {
            return Err(TransportError::InvalidLinkConfig {
                link_name: self.name.clone(),
                reason: "link name must not be empty".to_owned(),
            });
        }

        let is_bind = self.bind_addr.is_some();
        let is_connect = self.connect_addr.is_some();
        if is_bind == is_connect {
            // A link must choose one socket direction so startup can deterministically decide
            // whether to bind or connect instead of silently doing the wrong thing.
            return Err(TransportError::InvalidLinkConfig {
                link_name: self.name.clone(),
                reason: "exactly one of `bind_addr` or `connect_addr` must be set".to_owned(),
            });
        }

        if self.peer_instance_id.trim().is_empty() {
            return Err(TransportError::InvalidLinkConfig {
                link_name: self.name.clone(),
                reason: "peer_instance_id must not be empty".to_owned(),
            });
        }

        Ok(())
    }
}

/// One framed message queued for a specific named transport link.
///
/// # Why this exists
/// Runtime code routes concrete protocol frames by configured link name rather than by raw socket
/// handle, so it needs a small wrapper that keeps routing intent attached to the frame bytes.
#[derive(Debug, Clone)]
pub struct OutboundFrame {
    /// Manifest route name used to find the correct writer socket.
    pub link_name: String,
    /// Fully framed wire payload ready to send.
    pub frame: ProtocolFrame,
}

impl OutboundFrame {
    /// Creates an outbound frame wrapper for one named route.
    ///
    /// # Why this exists
    /// Some callers already hold a finished [`ProtocolFrame`] and only need to associate it with a
    /// route name.
    pub fn new(link_name: impl Into<String>, frame: ProtocolFrame) -> Self {
        Self {
            link_name: link_name.into(),
            frame,
        }
    }

    /// Encodes a typed wire message into an outbound frame for one route.
    ///
    /// # Why this exists
    /// Most runtime call sites start from typed control or protocol messages, not prebuilt frame
    /// bytes, so this keeps wire encoding and routing coupled at the transport boundary.
    ///
    /// # Errors
    /// Returns a transport error if the typed message cannot be serialized into a wire frame.
    pub fn from_message<M: WireMessage>(
        link_name: impl Into<String>,
        message: &M,
    ) -> Result<Self, TransportError> {
        let payload = message.encode_payload()?;
        let frame = ProtocolFrame::new(M::TAG, payload)?;
        Ok(Self::new(link_name, frame))
    }
}

/// One framed message received from a specific named link.
///
/// # Why this exists
/// Runtime dispatch needs both the incoming frame bytes and the link that delivered them so it can
/// enforce route-specific expectations.
#[derive(Debug)]
pub struct InboundFrame {
    /// Manifest link name that produced this frame.
    pub link_name: String,
    /// Raw received frame, preserved for typed decode by higher layers.
    pub frame: ProtocolFrame,
}

/// Map of manifest link names to bounded outbound writer queues.
///
/// # Why this exists
/// The runtime addresses routes by stable manifest name, while async socket writer tasks own the
/// actual TCP streams behind those route names.
pub type LinkWriters = BTreeMap<String, mpsc::Sender<ProtocolFrame>>;

/// Fully established transport resources for one process.
///
/// # Why this exists
/// Link establishment produces one inbound queue, one outbound queue per route, and the async
/// tasks that keep those queues synchronized with real sockets.
pub struct EstablishedLinks {
    /// Inbound frames delivered by per-link async read tasks.
    pub inbound_rx: mpsc::Receiver<InboundFrame>,
    /// Outbound route queues keyed by manifest link name.
    pub writers: LinkWriters,
    /// Background tasks that currently own the socket halves for this session.
    pub task_handles: Vec<JoinHandle<()>>,
}
