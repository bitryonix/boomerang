use cryptography::PublicKey;
use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Getters)]
#[getset(get = "pub with_prefix")]
pub struct InitiatorBoomletData {
    initiator_id: PublicKey,
}

impl InitiatorBoomletData {
    pub fn new(initiator_id: PublicKey) -> Self {
        InitiatorBoomletData { initiator_id }
    }
}
