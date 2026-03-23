use std::io;

use derive_more::Display;
use protocol_wire::{MessageTag, WireDecodeError, WireEncodeError, control::TransportRole};

/// Transport-layer failures produced while establishing or using TCP links.
///
/// # Why this exists
/// The transport crate needs a small typed error surface that callers can use to distinguish
/// configuration mistakes, handshake mismatches, wire-format issues, and ordinary socket failures.
///
/// # Role in the system
/// Returned by link validation, frame I/O, handshake helpers, and runtime-facing transport
/// services throughout this crate.
#[derive(Debug, Display)]
pub enum TransportError {
    /// The operating system rejected a transport I/O operation.
    ///
    /// Callers should usually surface this as an operational startup or link-failure error.
    #[display("i/o error: {_0}")]
    Io(io::Error),
    /// A typed wire message could not be serialized into a frame.
    ///
    /// Callers should treat this as a transport-contract violation or unexpected internal state.
    #[display("wire encode failed: {_0}")]
    WireEncode(WireEncodeError),
    /// Received bytes could not be decoded as a valid wire frame or typed wire message.
    ///
    /// Callers should assume the peer sent invalid or incompatible data and stop trusting that
    /// link until it is re-established.
    #[display("wire decode failed: {_0}")]
    WireDecode(WireDecodeError),
    /// A manifest or derived link definition violates transport invariants.
    #[display("invalid link configuration for `{link_name}`: {reason}")]
    InvalidLinkConfig { link_name: String, reason: String },
    /// The remote process reported a different role than the manifest expected.
    #[display(
        "link `{link_name}` connected to wrong role: expected {}, got {}",
        expected.as_str(),
        actual.as_str()
    )]
    UnexpectedHelloRole {
        link_name: String,
        expected: TransportRole,
        actual: TransportRole,
    },
    /// The remote process reported a different instance id than the manifest expected.
    #[display(
        "link `{link_name}` connected to wrong instance: expected `{expected}`, got `{actual}`"
    )]
    UnexpectedHelloInstance {
        link_name: String,
        expected: String,
        actual: String,
    },
    /// The remote process reported a different link name than the local endpoint expected.
    #[display(
        "link `{link_name}` handshake used wrong link name: expected `{expected}`, got `{actual}`"
    )]
    UnexpectedHelloLinkName {
        link_name: String,
        expected: String,
        actual: String,
    },
    /// Runtime code tried to send on a route name that has no established writer.
    #[display("role {} has no link named `{_0}`", _1.as_str())]
    UnknownLink(String, TransportRole),
    /// Runtime code tried to send on a route whose async writer task has already shut down.
    #[display("transport outbound channel for link `{link_name}` is closed")]
    OutboundChannelClosed { link_name: String },
    /// The runtime-facing inbound queue has been shut down.
    ///
    /// Callers should treat this as the transport session completing or failing and should stop
    /// waiting for more inbound frames from that session.
    #[display("transport inbound channel closed")]
    InboundChannelClosed,
    /// A transport operation took longer than its configured timeout budget.
    #[display("timed out during {operation} for link `{link_name}`")]
    OperationTimedOut {
        link_name: String,
        operation: &'static str,
    },
    /// A background transport task failed while the session was shutting down.
    #[display("transport background task failed during shutdown: {detail}")]
    BackgroundTaskFailed { detail: String },
    /// A link received a well-formed frame carrying a message tag that the caller did not expect.
    #[display("unexpected protocol tag {tag:?} received on link `{link_name}`")]
    UnexpectedProtocolTag { link_name: String, tag: MessageTag },
}

impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<WireEncodeError> for TransportError {
    fn from(value: WireEncodeError) -> Self {
        Self::WireEncode(value)
    }
}

impl From<WireDecodeError> for TransportError {
    fn from(value: WireDecodeError) -> Self {
        Self::WireDecode(value)
    }
}

impl std::error::Error for TransportError {}
