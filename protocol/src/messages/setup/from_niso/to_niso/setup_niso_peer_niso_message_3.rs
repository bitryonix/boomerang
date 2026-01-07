use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoPeerNisoMessage3 {
    shared_state_fingerprint_signed_by_boomlet: SignedData<[u8; 32]>,
}

impl SetupNisoPeerNisoMessage3 {
    pub fn new(shared_state_fingerprint_signed_by_boomlet: SignedData<[u8; 32]>) -> Self {
        SetupNisoPeerNisoMessage3 {
            shared_state_fingerprint_signed_by_boomlet,
        }
    }

    pub fn into_parts(self) -> (SignedData<[u8; 32]>,) {
        (self.shared_state_fingerprint_signed_by_boomlet,)
    }
}

impl Message for SetupNisoPeerNisoMessage3 {}
