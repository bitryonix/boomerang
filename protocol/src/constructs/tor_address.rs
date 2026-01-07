use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct TorAddress {
    onion_v3_address: String,
}

impl TorAddress {
    pub fn new(onion_v3_address: String) -> Self {
        TorAddress { onion_v3_address }
    }
}
