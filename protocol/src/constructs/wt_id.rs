use cryptography::PublicKey;
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::constructs::TorAddress;

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct WtId {
    wt_pubkey: PublicKey,
    wt_tor_address: TorAddress,
}

impl WtId {
    pub fn new(wt_pubkey: PublicKey, wt_tor_address: TorAddress) -> Self {
        WtId {
            wt_pubkey,
            wt_tor_address,
        }
    }
}
