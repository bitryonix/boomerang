use std::ops::Deref;

use bitcoin::key::rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{Level, event};
use tracing_utils::traceable_unfold_or_panic;

use crate::{PublicKey, SECP};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PrivateKey {
    inner: bitcoin::secp256k1::SecretKey,
}

impl PrivateKey {
    pub fn new(private_key: bitcoin::secp256k1::SecretKey) -> Self {
        Self { inner: private_key }
    }

    pub fn generate() -> Self {
        let mut rng = thread_rng();
        PrivateKey::new(bitcoin::secp256k1::SecretKey::new(&mut rng))
    }

    pub fn derive_public_key(&self) -> PublicKey {
        let secp = &SECP;
        PublicKey::new(self.inner.public_key(secp))
    }
}

impl Deref for PrivateKey {
    type Target = bitcoin::secp256k1::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<PrivateKey> for musig2::secp256k1::SecretKey {
    fn from(val: PrivateKey) -> Self {
        traceable_unfold_or_panic!(
            musig2::secp256k1::SecretKey::from_byte_array(val.inner.secret_bytes(),),
            "Assumed musig2::secp256k1 understands serialized private keys from bitcoin::secp256k1.",
        )
    }
}
