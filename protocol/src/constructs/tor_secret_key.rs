use std::fmt;

use ed25519_dalek::SigningKey;
use rand::random;
use serde::{Deserialize, Serialize};

use crate::constructs::TorAddress;

use super::tor_address::onion_address_from_public_key;

const TOR_HIDDEN_SERVICE_SECRET_KEY_LEN: usize = 64;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TorSecretKey {
    seed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorSecretKeyParseError {
    InvalidLength { expected: usize, actual: usize },
    PublicKeyMismatch,
}

impl fmt::Display for TorSecretKeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid Tor secret key length: expected {expected}, got {actual}"
                )
            }
            Self::PublicKeyMismatch => {
                write!(
                    f,
                    "Tor hidden-service public key does not match the secret seed"
                )
            }
        }
    }
}

impl std::error::Error for TorSecretKeyParseError {}

impl fmt::Debug for TorSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TorSecretKey")
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl TorSecretKey {
    pub fn new_random() -> Self {
        Self::from_seed_bytes(random())
    }

    pub fn from_seed_bytes(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn get_address(&self) -> TorAddress {
        let public_key_bytes = SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes();
        TorAddress::new(onion_address_from_public_key(public_key_bytes))
    }

    pub fn to_hidden_service_secret_key_bytes(&self) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(&self.seed);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let mut bytes = Vec::with_capacity(TOR_HIDDEN_SERVICE_SECRET_KEY_LEN);
        bytes.extend_from_slice(&self.seed);
        bytes.extend_from_slice(&public_key_bytes);
        bytes
    }

    pub fn from_hidden_service_secret_key_bytes(
        bytes: &[u8],
    ) -> Result<Self, TorSecretKeyParseError> {
        if bytes.len() != TOR_HIDDEN_SERVICE_SECRET_KEY_LEN {
            return Err(TorSecretKeyParseError::InvalidLength {
                expected: TOR_HIDDEN_SERVICE_SECRET_KEY_LEN,
                actual: bytes.len(),
            });
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let signing_key = SigningKey::from_bytes(&seed);
        let derived_public_key_bytes = signing_key.verifying_key().to_bytes();
        if bytes[32..] != derived_public_key_bytes {
            return Err(TorSecretKeyParseError::PublicKeyMismatch);
        }

        Ok(Self { seed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_real_onion_v3_address_from_seed_fixture() {
        let secret_key = TorSecretKey::from_seed_bytes([7u8; 32]);

        assert_eq!(
            secret_key.get_address().as_str(),
            "5jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwfmxqd.onion"
        );
    }

    #[test]
    fn serde_round_trips_secret_keys() {
        let secret_key = TorSecretKey::from_seed_bytes([9u8; 32]);
        let encoded =
            bincode::serde::encode_to_vec(&secret_key, bincode::config::standard()).unwrap();
        let (decoded, _): (TorSecretKey, usize) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

        assert_eq!(decoded, secret_key);
    }

    #[test]
    fn hidden_service_secret_key_bytes_round_trip() {
        let secret_key = TorSecretKey::from_seed_bytes([11u8; 32]);

        let decoded = TorSecretKey::from_hidden_service_secret_key_bytes(
            &secret_key.to_hidden_service_secret_key_bytes(),
        )
        .unwrap();

        assert_eq!(decoded, secret_key);
    }

    #[test]
    fn serde_round_trips_tor_addresses() {
        let address = TorSecretKey::from_seed_bytes([13u8; 32]).get_address();
        let encoded = bincode::serde::encode_to_vec(&address, bincode::config::standard()).unwrap();
        let (decoded, _): (TorAddress, usize) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

        assert_eq!(decoded, address);
    }
}
