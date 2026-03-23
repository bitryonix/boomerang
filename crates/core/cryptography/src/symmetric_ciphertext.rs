use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Getters, PartialEq, PartialOrd, Ord, Hash, Eq)]
#[getset(get = "pub with_prefix")]
pub struct SymmetricCiphertext {
    iv: [u8; 16],
    encrypted: Vec<u8>,
}

impl SymmetricCiphertext {
    pub fn new(iv: [u8; 16], encrypted: Vec<u8>) -> Self {
        SymmetricCiphertext { iv, encrypted }
    }
}
