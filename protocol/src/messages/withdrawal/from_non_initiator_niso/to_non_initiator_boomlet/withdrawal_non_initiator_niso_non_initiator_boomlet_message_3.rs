use bitcoin::absolute;
use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3 {
    tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: SymmetricCiphertext,
    niso_event_block_height: absolute::Height,
}

impl WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3 {
    pub fn new(
        tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: SymmetricCiphertext,
        niso_event_block_height: absolute::Height,
    ) -> Self {
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3 {
            tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
            niso_event_block_height,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext, absolute::Height) {
        (
            self.tx_id_st_check_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
            self.niso_event_block_height,
        )
    }
}

impl Message for WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3 {}
