use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorSarWtMessage1 {
    duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet: SymmetricCiphertext,
}

impl WithdrawalNonInitiatorSarWtMessage1 {
    pub fn new(
        duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet: SymmetricCiphertext,
    ) -> Self {
        WithdrawalNonInitiatorSarWtMessage1 {
            duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,)
    }
}

impl Message for WithdrawalNonInitiatorSarWtMessage1 {}
