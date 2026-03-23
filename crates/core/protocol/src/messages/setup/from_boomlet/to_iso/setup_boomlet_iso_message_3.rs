use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletIsoMessage3 {
    duress_check_space_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext,
}

impl SetupBoomletIsoMessage3 {
    pub fn new(
        duress_check_space_with_nonce_encrypted_by_boomlet_for_st: SymmetricCiphertext,
    ) -> Self {
        SetupBoomletIsoMessage3 {
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.duress_check_space_with_nonce_encrypted_by_boomlet_for_st,)
    }
}
