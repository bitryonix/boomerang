use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStNisoMessage1 {
    boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: SymmetricCiphertext,
}

impl SetupStNisoMessage1 {
    pub fn new(
        boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: SymmetricCiphertext,
    ) -> Self {
        SetupStNisoMessage1 {
            boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,)
    }
}

impl Message for SetupStNisoMessage1 {}
