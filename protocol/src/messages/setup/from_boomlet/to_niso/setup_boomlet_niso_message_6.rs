use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletNisoMessage6 {
    shared_state_fingerprint_signed_by_boomlet: SignedData<[u8; 32]>,
}

impl SetupBoomletNisoMessage6 {
    pub fn new(shared_state_fingerprint_signed_by_boomlet: SignedData<[u8; 32]>) -> Self {
        SetupBoomletNisoMessage6 {
            shared_state_fingerprint_signed_by_boomlet,
        }
    }

    pub fn into_parts(self) -> (SignedData<[u8; 32]>,) {
        (self.shared_state_fingerprint_signed_by_boomlet,)
    }
}

impl Message for SetupBoomletNisoMessage6 {}
