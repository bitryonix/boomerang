use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5 {
    duress_signal_index_with_nonce_encrypted_by_st_for_boomlet: SymmetricCiphertext,
}

impl WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5 {
    pub fn new(
        duress_signal_index_with_nonce_encrypted_by_st_for_boomlet: SymmetricCiphertext,
    ) -> Self {
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5 {
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,)
    }
}

impl Message for WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5 {}
