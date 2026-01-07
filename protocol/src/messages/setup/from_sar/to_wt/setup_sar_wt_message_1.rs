use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupSarWtMessage1 {
    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet: SymmetricCiphertext,
}

impl SetupSarWtMessage1 {
    pub fn new(
        doxing_data_identifier_signed_by_sar_encrypted_by_sar_for_boomlet: SymmetricCiphertext,
    ) -> Self {
        SetupSarWtMessage1 {
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet:
                doxing_data_identifier_signed_by_sar_encrypted_by_sar_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet,)
    }
}

impl Message for SetupSarWtMessage1 {}
