use cryptography::PublicKey;
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::constructs::TorAddress;

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct SarId {
    sar_pubkey: PublicKey,
    sar_tor_address: TorAddress,
}

impl SarId {
    pub fn new(sar_pubkey: PublicKey, sar_tor_address: TorAddress) -> Self {
        SarId {
            sar_pubkey,
            sar_tor_address,
        }
    }
}
