use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6 {
    boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt:
        SymmetricCiphertext,
}

impl WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6 {
    pub fn new(
        boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
    ) -> Self {
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6 {
            boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (
            self.boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        )
    }
}

impl Message for WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6 {}
