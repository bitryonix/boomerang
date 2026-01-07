use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoWtMessage2 {
    initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt:
        SymmetricCiphertext,
}

impl WithdrawalNisoWtMessage2 {
    pub fn new(
        initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
    ) -> Self {
        WithdrawalNisoWtMessage2 {
            initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (
            self.initiator_boomlet_tx_commit_signed_by_boomlet_padded_signed_by_boomlet_encrypted_by_boomlet_for_wt,
        )
    }
}

impl Message for WithdrawalNisoWtMessage2 {}
