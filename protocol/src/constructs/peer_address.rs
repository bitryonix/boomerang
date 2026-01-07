use cryptography::SignedData;
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::constructs::{PeerId, TorAddress};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Getters)]
#[getset(get = "pub with_prefix")]
pub struct PeerAddress {
    peer_id: PeerId,
    peer_tor_address_signed_by_boomlet: SignedData<TorAddress>,
}

impl PeerAddress {
    pub fn new(
        peer_id: PeerId,
        peer_tor_address_signed_by_boomlet: SignedData<TorAddress>,
    ) -> Self {
        PeerAddress {
            peer_id,
            peer_tor_address_signed_by_boomlet,
        }
    }
}
