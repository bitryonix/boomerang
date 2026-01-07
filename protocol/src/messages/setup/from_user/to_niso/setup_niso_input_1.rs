use std::net::SocketAddrV4;

use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::{constructs::BitcoinCoreAuth, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoInput1 {
    network: Network,
    rpc_client_url: SocketAddrV4,
    rpc_client_auth: BitcoinCoreAuth,
}

impl SetupNisoInput1 {
    pub fn new(
        network: Network,
        rpc_client_url: SocketAddrV4,
        rpc_client_auth: BitcoinCoreAuth,
    ) -> Self {
        SetupNisoInput1 {
            network,
            rpc_client_url,
            rpc_client_auth,
        }
    }

    pub fn into_parts(self) -> (Network, SocketAddrV4, BitcoinCoreAuth) {
        (self.network, self.rpc_client_url, self.rpc_client_auth)
    }
}

impl Message for SetupNisoInput1 {}
