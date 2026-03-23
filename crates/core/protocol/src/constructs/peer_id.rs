use cryptography::PublicKey;
use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct PeerId {
    boom_pubkey: PublicKey,
    normal_pubkey: PublicKey,
    boomlet_identity_pubkey: PublicKey,
}

impl PeerId {
    pub fn new(
        boom_pubkey: PublicKey,
        normal_pubkey: PublicKey,
        boomlet_identity_pubkey: PublicKey,
    ) -> Self {
        PeerId {
            boom_pubkey,
            normal_pubkey,
            boomlet_identity_pubkey,
        }
    }
}
