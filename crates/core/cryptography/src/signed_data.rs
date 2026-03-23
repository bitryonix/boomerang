use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::{
    Cryptography, CryptographySignatureVerificationError, PrivateKey, PublicKey, Signature,
};

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[allow(clippy::derived_hash_with_manual_eq)]
pub struct SignedData<T: Serialize + PartialEq> {
    data: T,
    signature: Signature,
}

impl<T: Serialize + PartialEq> SignedData<T> {
    pub fn sign_and_bundle(data: T, privkey: &PrivateKey) -> Self {
        let signature = Cryptography::sign(&data, privkey);
        Self { data, signature }
    }

    pub fn verify_and_unbundle(
        self,
        pubkey: &PublicKey,
    ) -> Result<T, CryptographySignatureVerificationError> {
        Cryptography::verify(&self.data, &self.signature, pubkey)?;
        Ok(self.data)
    }

    pub fn verify(&self, pubkey: &PublicKey) -> Result<(), CryptographySignatureVerificationError> {
        Cryptography::verify(&self.data, &self.signature, pubkey)?;
        Ok(())
    }

    pub fn unbundle(self) -> T {
        self.data
    }

    pub fn peek_data(&self) -> &T {
        &self.data
    }

    pub fn peek_signature(&self) -> &Signature {
        &self.signature
    }
}

impl<T> PartialEq for SignedData<T>
where
    T: Serialize + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<T> Eq for SignedData<T> where T: Serialize + Eq {}

impl<T> PartialOrd for SignedData<T>
where
    T: Serialize + PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.data.partial_cmp(&other.data)
    }
}

impl<T> Ord for SignedData<T>
where
    T: Serialize + Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.cmp(&other.data)
    }
}
