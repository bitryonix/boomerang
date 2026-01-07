use cryptography::PublicKey;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStIsoMessage1 {
    st_identity_pubkey: PublicKey,
}

impl SetupStIsoMessage1 {
    pub fn new(st_identity_pubkey: PublicKey) -> Self {
        SetupStIsoMessage1 { st_identity_pubkey }
    }

    pub fn into_parts(self) -> (PublicKey,) {
        (self.st_identity_pubkey,)
    }
}

impl Message for SetupStIsoMessage1 {}
