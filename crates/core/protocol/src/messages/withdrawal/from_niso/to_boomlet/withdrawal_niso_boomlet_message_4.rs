use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoBoomletMessage4 {
    duress_signal_index_with_nonce_encrypted_by_st_for_boomlet: SymmetricCiphertext,
}

impl WithdrawalNisoBoomletMessage4 {
    pub fn new(
        duress_signal_index_with_nonce_encrypted_by_st_for_boomlet: SymmetricCiphertext,
    ) -> Self {
        WithdrawalNisoBoomletMessage4 {
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.duress_signal_index_with_nonce_encrypted_by_st_for_boomlet,)
    }
}
