#![forbid(unsafe_code)]

//! Stable frame encoding and transport control payloads for Boomerang.
//!
//! # Why this exists
//! The domain `protocol` crate models business messages, while this crate owns the framed wire
//! contract and transport-only payloads used to move those messages between processes.
//!
//! # Role in the system
//! `boomerang-transport` and `boomerang-runtime` depend on this crate for tag registries, frame
//! encoding, and control messages like `TransportHello`.

mod codec;
pub mod control;

pub use codec::*;
