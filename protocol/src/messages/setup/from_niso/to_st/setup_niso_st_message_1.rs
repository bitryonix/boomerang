use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{PeerId, TorAddress},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoStMessage1 {
    peer_id: PeerId,
    peer_tor_address_signed_by_boomlet: SignedData<TorAddress>,
}

impl SetupNisoStMessage1 {
    pub fn new(
        peer_id: PeerId,
        peer_tor_address_signed_by_boomlet: SignedData<TorAddress>,
    ) -> Self {
        SetupNisoStMessage1 {
            peer_id,
            peer_tor_address_signed_by_boomlet,
        }
    }

    pub fn into_parts(self) -> (PeerId, SignedData<TorAddress>) {
        (self.peer_id, self.peer_tor_address_signed_by_boomlet)
    }
}

impl Message for SetupNisoStMessage1 {}
