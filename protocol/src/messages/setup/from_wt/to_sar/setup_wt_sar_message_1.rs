use cryptography::{PublicKey, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupWtSarMessage1 {
    doxing_data_identifier_encrypted_by_boomlet_for_sar: SymmetricCiphertext,
    boomlet_identity_pubkey: PublicKey,
}

impl SetupWtSarMessage1 {
    pub fn new(
        doxing_data_identifier_encrypted_by_boomlet_for_sar: SymmetricCiphertext,
        boomlet_identity_pubkey: PublicKey,
    ) -> Self {
        SetupWtSarMessage1 {
            doxing_data_identifier_encrypted_by_boomlet_for_sar,
            boomlet_identity_pubkey,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext, PublicKey) {
        (
            self.doxing_data_identifier_encrypted_by_boomlet_for_sar,
            self.boomlet_identity_pubkey,
        )
    }
}

impl Message for SetupWtSarMessage1 {}
