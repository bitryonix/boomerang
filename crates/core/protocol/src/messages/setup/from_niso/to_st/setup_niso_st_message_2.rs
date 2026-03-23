use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoStMessage2 {
    boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext,
}

impl SetupNisoStMessage2 {
    pub fn new(
        boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext,
    ) -> Self {
        SetupNisoStMessage2 {
            boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,)
    }
}
