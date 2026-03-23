use cryptography::SymmetricCiphertext;
use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Hash, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct WtSarSetupResponse {
    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet: SymmetricCiphertext,
    wt_suffix: String,
}

impl WtSarSetupResponse {
    pub fn new(
        sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet: SymmetricCiphertext,
        wt_suffix: String,
    ) -> Self {
        WtSarSetupResponse {
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet,
            wt_suffix,
        }
    }
}
