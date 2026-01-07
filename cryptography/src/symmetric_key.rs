use std::ops::Deref;

use serde::{Deserialize, Serialize};

use crate::Cryptography;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymmetricKey {
    inner: [u8; 32],
}

impl SymmetricKey {
    pub fn from_hashing_a_password(password: &str) -> Self {
        SymmetricKey {
            inner: Cryptography::hash(&password),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SymmetricKey { inner: *bytes }
    }
}

impl Deref for SymmetricKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
