use cryptography::PublicKey;
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::constructs::TorAddress;

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct WtPeerId {
    boomlet_identity_pubkey: PublicKey,
    peer_tor_address: TorAddress,
    boomerang_params_fingerprint: [u8; 32],
}

impl WtPeerId {
    pub fn new(
        boomlet_identity_pubkey: PublicKey,
        peer_tor_address: TorAddress,
        boomerang_params_fingerprint: [u8; 32],
    ) -> Self {
        WtPeerId {
            boomlet_identity_pubkey,
            peer_tor_address,
            boomerang_params_fingerprint,
        }
    }
}
