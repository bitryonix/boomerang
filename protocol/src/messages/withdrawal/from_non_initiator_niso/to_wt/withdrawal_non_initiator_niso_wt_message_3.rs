use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoWtMessage3 {
    boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt:
        SymmetricCiphertext,
}

impl WithdrawalNonInitiatorNisoWtMessage3 {
    pub fn new(
        boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
    ) -> Self {
        WithdrawalNonInitiatorNisoWtMessage3 {
            boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (
            self.boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        )
    }
}

impl Message for WithdrawalNonInitiatorNisoWtMessage3 {}
