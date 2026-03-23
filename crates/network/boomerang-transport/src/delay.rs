//! Delay-injection hooks for transport experiments.
//!
//! # Why this exists
//! The async runtime work needs a non-core seam for timing experiments so future PoC scenarios
//! can simulate latency and jitter without pushing that concern into the protocol entities.
//!
//! # Role in the system
//! [`LinkDelayPolicy`] is consumed by the TCP transport backend during connect, accept,
//! handshake, inbound delivery, and outbound delivery steps.

use std::time::Duration;

use protocol_wire::ProtocolFrame;

use crate::transport::LinkConfig;

/// Supplies optional delays for transport operations.
///
/// # Why this exists
/// Tests and future PoC scenarios need a deterministic place to inject timing skew while leaving
/// the current production path unchanged by default.
pub trait LinkDelayPolicy: Send + Sync {
    /// Delay before an outbound connect attempt starts.
    fn connect_delay(&self, _link: &LinkConfig) -> Duration {
        Duration::ZERO
    }

    /// Delay before a bind-mode link accepts an inbound peer.
    fn accept_delay(&self, _link: &LinkConfig) -> Duration {
        Duration::ZERO
    }

    /// Delay before a handshake step proceeds.
    fn handshake_delay(&self, _link: &LinkConfig) -> Duration {
        Duration::ZERO
    }

    /// Delay before a received frame is handed to the runtime driver.
    fn inbound_delivery_delay(&self, _link_name: &str, _frame: &ProtocolFrame) -> Duration {
        Duration::ZERO
    }

    /// Delay before a queued outbound frame is written to the socket.
    fn outbound_delivery_delay(&self, _link_name: &str, _frame: &ProtocolFrame) -> Duration {
        Duration::ZERO
    }
}

/// Default no-op delay policy used by the supported runtime path.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDelayLinkDelayPolicy;

impl LinkDelayPolicy for NoDelayLinkDelayPolicy {}
