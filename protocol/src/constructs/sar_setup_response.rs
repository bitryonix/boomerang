use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Hash, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct SarSetupResponse {
    doxing_data_identifier: [u8; 32],
    fingerprint_of_static_doxing_data_encrypted_by_doxing_key: [u8; 32],
    static_doxing_data_encrypted_by_doxing_key_iv: [u8; 16],
}

impl SarSetupResponse {
    pub fn new(
        doxing_data_identifier: [u8; 32],
        fingerprint_of_static_doxing_data_encrypted_by_doxing_key: [u8; 32],
        static_doxing_data_encrypted_by_doxing_key_iv: [u8; 16],
    ) -> Self {
        SarSetupResponse {
            doxing_data_identifier,
            fingerprint_of_static_doxing_data_encrypted_by_doxing_key,
            static_doxing_data_encrypted_by_doxing_key_iv,
        }
    }
}
