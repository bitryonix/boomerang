//! TCP transport primitives for standalone Boomerang processes.
//!
//! # Why this exists
//! The runtime needs a small, well-defined layer that owns sockets, link validation, frame I/O,
//! and the transport handshake without leaking those details into role orchestration.
//!
//! # Role in the system
//! [`crate`] sits between the wire contract in [`protocol_wire`] and the higher-level process
//! coordination in `boomerang-runtime`.
//!
//! # Example
//! A process manifest resolves to [`LinkConfig`] values, the runtime calls [`establish_links`] to
//! complete the TCP handshakes, and then it uses the returned session queues to exchange framed
//! protocol messages.

mod handshake;
mod io;
mod model;
mod service;
#[cfg(test)]
mod tests;

pub use io::{read_frame, write_frame};
pub use model::{
    EstablishedLinks, InboundFrame, LinkConfig, LinkWriters, LocalProcessIdentity, OutboundFrame,
};
pub(crate) use service::establish_links_with_delay;
pub use service::{establish_links, write_outbound_frame};
