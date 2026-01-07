use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2 {
    tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext,
}

impl WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2 {
    pub fn new(tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext) -> Self {
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2 {
            tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.tx_id_st_check_with_nonce_encrypted_by_boomlet_for_st,)
    }
}

impl Message for WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2 {}
