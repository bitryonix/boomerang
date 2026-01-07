use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBoomletNisoMessage7 {
    boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt:
        SymmetricCiphertext,
}

impl WithdrawalBoomletNisoMessage7 {
    pub fn new(
        boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
    ) -> Self {
        WithdrawalBoomletNisoMessage7 {
            boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (
            self.boomlet_ping_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        )
    }
}

impl Message for WithdrawalBoomletNisoMessage7 {}
