use std::{ops::Deref, sync::LazyLock};

use aes::{
    Aes256,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7},
};
use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::{self, All, ecdh::SharedSecret},
};
use cbc::{Decryptor, Encryptor};
use derive_more::{Display, Error};
use rand::Rng;
use serde::{Serialize, de::DeserializeOwned};
use sha2::Digest;
use tracing::{Level, event};
use tracing_utils::traceable_unfold_or_panic;

use crate::{
    BytePacker, BytePackerDecodeError, PrivateKey, PublicKey, Signature, SymmetricCiphertext,
    SymmetricKey,
};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

pub struct Cryptography;

impl Cryptography {
    pub fn hash(content: &impl Serialize) -> [u8; 32] {
        sha2::Sha256::digest(BytePacker::byte_pack(content)).into()
    }

    pub fn sign(content: &impl Serialize, privkey: &PrivateKey) -> Signature {
        let secp = &SECP;
        let sighash = Cryptography::hash(content);
        let message = traceable_unfold_or_panic!(
            bitcoin::secp256k1::Message::from_digest_slice(sighash.as_slice()),
            "Assumed Sha256 to hash to exactly 32 bytes.",
        );
        let keypair = Keypair::from_secret_key(secp, privkey);
        Signature::new(secp.sign_schnorr(&message, &keypair))
    }

    pub fn verify(
        content: &impl Serialize,
        signature: &Signature,
        pubkey: &PublicKey,
    ) -> Result<(), CryptographySignatureVerificationError> {
        let secp = &SECP;
        let sighash = Cryptography::hash(content);
        let message = traceable_unfold_or_panic!(
            bitcoin::secp256k1::Message::from_digest_slice(sighash.as_slice()),
            "Assumed Sha256 to hash to exactly 32 bytes.",
        );
        secp.verify_schnorr(signature, &message, &pubkey.x_only_public_key().0)
            .map_err(CryptographySignatureVerificationError)
    }

    pub fn symmetric_encrypt(
        plaintext: &impl Serialize,
        symmetric_key: &SymmetricKey,
    ) -> Result<SymmetricCiphertext, CryptographySymmetricEncryptionError> {
        let mut rng = rand::rng();
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let cipher = Aes256CbcEnc::new(symmetric_key.deref().into(), &iv.into());
        let encrypted = cipher.encrypt_padded_vec_mut::<Pkcs7>(&BytePacker::byte_pack(plaintext));
        Ok(SymmetricCiphertext::new(iv, encrypted))
    }

    pub fn symmetric_encrypt_with_iv(
        plaintext: &impl Serialize,
        symmetric_key: &SymmetricKey,
        iv: &[u8; 16],
    ) -> Result<SymmetricCiphertext, CryptographySymmetricEncryptionError> {
        let cipher = Aes256CbcEnc::new(symmetric_key.deref().into(), iv.into());
        let encrypted = cipher.encrypt_padded_vec_mut::<Pkcs7>(&BytePacker::byte_pack(plaintext));
        Ok(SymmetricCiphertext::new(*iv, encrypted))
    }

    pub fn symmetric_decrypt<D: DeserializeOwned>(
        ciphertext: &SymmetricCiphertext,
        symmetric_key: &SymmetricKey,
    ) -> Result<D, CryptographySymmetricDecryptionError> {
        let cipher = Aes256CbcDec::new(symmetric_key.deref().into(), ciphertext.get_iv().into());
        let decrypted = cipher
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext.get_encrypted())
            .map_err(|_err| CryptographySymmetricDecryptionError::Aes)?;
        let deserialized = BytePacker::byte_unpack(&decrypted)
            .map_err(CryptographySymmetricDecryptionError::Deserialization)?;
        Ok(deserialized)
    }

    pub fn diffie_hellman(privkey: &PrivateKey, pubkey: &PublicKey) -> SymmetricKey {
        SymmetricKey::from_bytes(&SharedSecret::new(pubkey, privkey).secret_bytes())
    }
}

#[derive(Debug, Display, Error)]
pub struct CryptographySignatureVerificationError(secp256k1::Error);

#[derive(Debug, Display, Error)]
pub enum CryptographySymmetricEncryptionError {
    Aes,
}

#[derive(Debug, Display, Error)]
pub enum CryptographySymmetricDecryptionError {
    Aes,
    Deserialization(BytePackerDecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature() {
        // Arrange
        let private_key = PrivateKey::generate();
        let public_key = private_key.derive_public_key();
        let content = String::from("Hello World!");

        // Action
        let signature = Cryptography::sign(&content, &private_key);

        // Assert
        assert!(Cryptography::verify(&content, &signature, &public_key).is_ok());
    }

    #[test]
    fn test_symmetric_encryption() {
        // Arrange
        let symmetric_key =
            SymmetricKey::from_hashing_a_password(&String::from("!30d390sIW919Wo#8"));
        let content = String::from("Hello World!");

        // Action
        let ciphertext = Cryptography::symmetric_encrypt(&content, &symmetric_key).unwrap();
        let deciphered_content =
            Cryptography::symmetric_decrypt::<String>(&ciphertext, &symmetric_key).unwrap();

        // Assert
        assert_eq!(content, deciphered_content);
    }

    #[test]
    fn test_diffie_hellman() {
        // Arrange
        let private_key_1 = PrivateKey::generate();
        let public_key_1 = private_key_1.derive_public_key();
        let private_key_2 = PrivateKey::generate();
        let public_key_2 = private_key_2.derive_public_key();

        // Action
        let symmetric_key_1 = Cryptography::diffie_hellman(&private_key_1, &public_key_2);
        let symmetric_key_2 = Cryptography::diffie_hellman(&private_key_2, &public_key_1);

        // Assert
        assert_eq!(symmetric_key_1, symmetric_key_2);
    }
}
