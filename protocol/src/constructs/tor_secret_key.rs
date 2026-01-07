use bitcoin::key::rand::{Rng, thread_rng};
use cryptography::Cryptography;
use serde::{Deserialize, Serialize};

use crate::constructs::TorAddress;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorSecretKey {
    inner: [u8; 32],
}

impl TorSecretKey {
    pub fn new_random() -> Self {
        let mut rng = thread_rng();
        let mut inner = [0u8; 32];
        rng.fill(&mut inner);
        TorSecretKey { inner }
    }

    pub fn get_address(&self) -> TorAddress {
        let onion_v3_address = hex::encode(Cryptography::hash(&self.inner));
        TorAddress::new(onion_v3_address)
    }
}
