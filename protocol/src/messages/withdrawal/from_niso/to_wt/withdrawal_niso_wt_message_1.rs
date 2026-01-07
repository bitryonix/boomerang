use std::collections::BTreeMap;

use cryptography::{PublicKey, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoWtMessage1 {
    boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
    psbt_encrypted_collection: BTreeMap<PublicKey, SymmetricCiphertext>,
}

impl WithdrawalNisoWtMessage1 {
    pub fn new(
        boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
        psbt_encrypted_collection: BTreeMap<PublicKey, SymmetricCiphertext>,
    ) -> Self {
        WithdrawalNisoWtMessage1 {
            boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
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
            self.boomlet_tx_approval_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            self.psbt_encrypted_collection,
        )
    }
}

impl Message for WithdrawalNisoWtMessage1 {}
