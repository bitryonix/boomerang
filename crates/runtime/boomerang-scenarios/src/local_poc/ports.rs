//! Port-allocation helpers for the local loopback topology.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::error::LocalPocError;

/// Converts one port number into the loopback socket address used by the local POC.
pub(super) fn next_socket_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

/// Advances the next free port and reports overflow as a typed build error.
pub(super) fn advance_port(port: &mut u16, phase: &'static str) -> Result<(), LocalPocError> {
    *port = port
        .checked_add(1)
        .ok_or(LocalPocError::PortAllocationOverflow { phase })?;
    Ok(())
}
