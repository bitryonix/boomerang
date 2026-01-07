use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoBoomletMessage3 {
    duress_answer_indices_encrypted_by_st_for_boomlet: SymmetricCiphertext,
}

impl SetupIsoBoomletMessage3 {
    pub fn new(duress_answer_indices_encrypted_by_st_for_boomlet: SymmetricCiphertext) -> Self {
        SetupIsoBoomletMessage3 {
            duress_answer_indices_encrypted_by_st_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext,) {
        (self.duress_answer_indices_encrypted_by_st_for_boomlet,)
    }
}

impl Message for SetupIsoBoomletMessage3 {}
