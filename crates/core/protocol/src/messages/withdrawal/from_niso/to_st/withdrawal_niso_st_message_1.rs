use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoStMessage1 {
    tx_id_st_check_encrypted_by_boomlet_for_st: SymmetricCiphertext,
}

impl WithdrawalNisoStMessage1 {
    pub fn new(tx_id_st_check_encrypted_by_boomlet_for_st: SymmetricCiphertext) -> Self {
        WithdrawalNisoStMessage1 {
            tx_id_st_check_encrypted_by_boomlet_for_st,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.tx_id_st_check_encrypted_by_boomlet_for_st,)
    }
}
