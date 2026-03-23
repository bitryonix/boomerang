#![forbid(unsafe_code)]

//! TCP transport support for standalone Boomerang processes.
//!
//! # Why this exists
//! The workspace needs a crate that owns sockets, handshake validation, and frame-oriented
//! transport concerns without mixing them into business protocol modeling or role orchestration.
//! It also now exposes backend-neutral transport ports so the runtime can grow beyond the current
//! TCP implementation without redesigning its process orchestration layer.
//!
//! # Role in the system
//! [`crate`] sits between [`protocol_wire`] and `boomerang-runtime`: it validates link configs,
//! establishes transport sessions, performs the current TCP handshake, and exposes framed
//! reader/writer helpers.
//!
//! # Example
//! A runtime loads manifest links and asks the default TCP backend to establish one fully
//! connected session:
//!
//! ```text
//! let session = transport.establish_session(&local, &links, progress_path).await?;
//! ```

pub mod delay;
pub mod error;
mod interface;
pub mod tcp;
mod transport;

pub use delay::{LinkDelayPolicy, NoDelayLinkDelayPolicy};
pub use error::TransportError;
pub use interface::{TransportInterface, TransportSession, TransportSessionFuture};
pub use tcp::{
    EstablishedLinks, InboundFrame, LinkConfig, LinkWriters, LocalProcessIdentity, OutboundFrame,
    TcpTransportInterface, TcpTransportSession, establish_links, write_outbound_frame,
};
pub use transport::{read_frame, write_frame};
