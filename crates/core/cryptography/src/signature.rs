use std::ops::Deref;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash)]
pub struct Signature {
    inner: bitcoin::secp256k1::schnorr::Signature,
}

impl Signature {
    pub(crate) fn new(inner: bitcoin::secp256k1::schnorr::Signature) -> Signature {
        Signature { inner }
    }
}

impl Deref for Signature {
    type Target = bitcoin::secp256k1::schnorr::Signature;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
