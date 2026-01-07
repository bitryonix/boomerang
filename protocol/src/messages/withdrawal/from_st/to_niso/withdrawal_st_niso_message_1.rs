use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalStNisoMessage1 {
    tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: SymmetricCiphertext,
}

impl WithdrawalStNisoMessage1 {
    pub fn new(
        tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: SymmetricCiphertext,
    ) -> Self {
        WithdrawalStNisoMessage1 {
            tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,)
    }
}

impl Message for WithdrawalStNisoMessage1 {}
