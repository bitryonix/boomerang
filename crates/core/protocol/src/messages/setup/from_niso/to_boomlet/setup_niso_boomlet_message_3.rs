use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoBoomletMessage3 {
    boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: SymmetricCiphertext,
}

impl SetupNisoBoomletMessage3 {
    pub fn new(
        boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet: SymmetricCiphertext,
    ) -> Self {
        SetupNisoBoomletMessage3 {
            boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.boomerang_params_seed_with_nonce_signed_by_st_encrypted_by_st_for_boomlet,)
    }
}
