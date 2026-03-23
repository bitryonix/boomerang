//! Concrete TCP transport adapter for the generic transport ports.
//!
//! # Why this exists
//! The workspace's supported production path runs over Tokio TCP with one async read task and one
//! async write task per link. This module packages that implementation behind the generic
//! transport traits so future backends can be added without changing runtime orchestration.
//!
//! # Role in the system
//! `boomerang-runtime` uses [`TcpTransportInterface`] as the default backend when callers select
//! the stable `run_process` path.

mod session;
#[cfg(test)]
mod tests;

pub use crate::transport::{
    EstablishedLinks, InboundFrame, LinkConfig, LinkWriters, LocalProcessIdentity, OutboundFrame,
    establish_links, write_outbound_frame,
};
pub use session::{TcpTransportInterface, TcpTransportSession};
