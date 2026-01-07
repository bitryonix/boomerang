use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletNisoMessage2 {
    boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext,
}

impl SetupBoomletNisoMessage2 {
    pub fn new(
        boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext,
    ) -> Self {
        SetupBoomletNisoMessage2 {
            boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.boomerang_params_seed_with_nonce_encrypted_by_boomlet_for_st,)
    }
}

impl Message for SetupBoomletNisoMessage2 {}
