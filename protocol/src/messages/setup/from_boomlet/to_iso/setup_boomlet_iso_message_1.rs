use cryptography::PublicKey;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletIsoMessage1 {
    boomlet_identity_pubkey: PublicKey,
}

impl SetupBoomletIsoMessage1 {
    pub fn new(boomlet_identity_pubkey: PublicKey) -> Self {
        SetupBoomletIsoMessage1 {
            boomlet_identity_pubkey,
        }
    }

    pub fn into_parts(self) -> (PublicKey,) {
        (self.boomlet_identity_pubkey,)
    }
}

impl Message for SetupBoomletIsoMessage1 {}
