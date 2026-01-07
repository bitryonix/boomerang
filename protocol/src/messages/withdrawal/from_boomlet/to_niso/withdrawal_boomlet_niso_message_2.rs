use std::collections::BTreeMap;

use cryptography::{PublicKey, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBoomletNisoMessage2 {
    initiator_boomlet_tx_approval_signed_by_initiator_boomlet_encrypted_by_boomlet_for_wt:
        SymmetricCiphertext,
    psbt_encrypted_collection: BTreeMap<PublicKey, SymmetricCiphertext>,
}

impl WithdrawalBoomletNisoMessage2 {
    pub fn new(
        initiator_boomlet_tx_approval_signed_by_initiator_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
        psbt_encrypted_collection: BTreeMap<PublicKey, SymmetricCiphertext>,
    ) -> Self {
        WithdrawalBoomletNisoMessage2 {
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet_encrypted_by_boomlet_for_wt,
            psbt_encrypted_collection,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        SymmetricCiphertext,
        BTreeMap<PublicKey, SymmetricCiphertext>,
    ) {
        (
            self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet_encrypted_by_boomlet_for_wt,
            self.psbt_encrypted_collection,
        )
    }
}

impl Message for WithdrawalBoomletNisoMessage2 {}
