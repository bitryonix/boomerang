use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoNonInitiatorStMessage1 {
    tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext,
}

impl WithdrawalNonInitiatorNisoNonInitiatorStMessage1 {
    pub fn new(tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext) -> Self {
        WithdrawalNonInitiatorNisoNonInitiatorStMessage1 {
            tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,)
    }
}
