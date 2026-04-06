use std::{fmt, str::FromStr};

use data_encoding::BASE32_NOPAD;
use getset::Getters;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};

pub(crate) const ONION_V3_VERSION: u8 = 0x03;
const ONION_V3_CHECKSUM_PREFIX: &[u8] = b".onion checksum";
const ONION_V3_SERVICE_ID_LEN: usize = 56;
const ONION_V3_ADDRESS_SUFFIX: &str = ".onion";
const ONION_V3_ADDRESS_DECODED_LEN: usize = 35;
const ONION_V3_PUBLIC_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorAddressParseError {
    MissingOnionSuffix,
    InvalidServiceIdLength { expected: usize, actual: usize },
    InvalidBase32Encoding,
    InvalidDecodedLength { expected: usize, actual: usize },
    UnsupportedOnionVersion(u8),
    InvalidChecksum,
}

impl fmt::Display for TorAddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOnionSuffix => write!(f, "Tor onion address must end with .onion"),
            Self::InvalidServiceIdLength { expected, actual } => write!(
                f,
                "Tor onion service id must be {expected} base32 characters, got {actual}"
            ),
            Self::InvalidBase32Encoding => {
                write!(f, "Tor onion service id is not valid base32")
            }
            Self::InvalidDecodedLength { expected, actual } => write!(
                f,
                "Tor onion service id must decode to {expected} bytes, got {actual}"
            ),
            Self::UnsupportedOnionVersion(version) => {
                write!(f, "Unsupported Tor onion version byte: {version}")
            }
            Self::InvalidChecksum => write!(f, "Tor onion address checksum is invalid"),
        }
    }
}

impl std::error::Error for TorAddressParseError {}

pub(crate) fn onion_address_from_public_key(
    public_key_bytes: [u8; ONION_V3_PUBLIC_KEY_LEN],
) -> String {
    let checksum = onion_checksum(&public_key_bytes, ONION_V3_VERSION);
    let mut address_bytes = [0u8; ONION_V3_ADDRESS_DECODED_LEN];
    address_bytes[..ONION_V3_PUBLIC_KEY_LEN].copy_from_slice(&public_key_bytes);
    address_bytes[ONION_V3_PUBLIC_KEY_LEN..ONION_V3_PUBLIC_KEY_LEN + 2].copy_from_slice(&checksum);
    address_bytes[ONION_V3_ADDRESS_DECODED_LEN - 1] = ONION_V3_VERSION;

    format!(
        "{}{ONION_V3_ADDRESS_SUFFIX}",
        BASE32_NOPAD.encode(&address_bytes).to_lowercase()
    )
}

fn onion_checksum(public_key_bytes: &[u8; ONION_V3_PUBLIC_KEY_LEN], version: u8) -> [u8; 2] {
    let mut hasher = Sha3_256::new();
    hasher.update(ONION_V3_CHECKSUM_PREFIX);
    hasher.update(public_key_bytes);
    hasher.update([version]);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

#[derive(Debug, Hash, Clone, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct TorAddress {
    onion_v3_address: String,
}

impl TorAddress {
    pub fn new(onion_v3_address: String) -> Result<Self, TorAddressParseError> {
        Self::try_new(onion_v3_address)
    }

    pub fn try_new(onion_v3_address: impl Into<String>) -> Result<Self, TorAddressParseError> {
        let onion_v3_address = onion_v3_address.into().trim().to_lowercase();
        let Some(service_id) = onion_v3_address.strip_suffix(ONION_V3_ADDRESS_SUFFIX) else {
            return Err(TorAddressParseError::MissingOnionSuffix);
        };
        if service_id.len() != ONION_V3_SERVICE_ID_LEN {
            return Err(TorAddressParseError::InvalidServiceIdLength {
                expected: ONION_V3_SERVICE_ID_LEN,
                actual: service_id.len(),
            });
        }

        let decoded = BASE32_NOPAD
            .decode(service_id.to_ascii_uppercase().as_bytes())
            .map_err(|_| TorAddressParseError::InvalidBase32Encoding)?;
        if decoded.len() != ONION_V3_ADDRESS_DECODED_LEN {
            return Err(TorAddressParseError::InvalidDecodedLength {
                expected: ONION_V3_ADDRESS_DECODED_LEN,
                actual: decoded.len(),
            });
        }

        let version = decoded[ONION_V3_ADDRESS_DECODED_LEN - 1];
        if version != ONION_V3_VERSION {
            return Err(TorAddressParseError::UnsupportedOnionVersion(version));
        }

        let mut public_key_bytes = [0u8; ONION_V3_PUBLIC_KEY_LEN];
        public_key_bytes.copy_from_slice(&decoded[..ONION_V3_PUBLIC_KEY_LEN]);
        let checksum = onion_checksum(&public_key_bytes, version);
        if decoded[ONION_V3_PUBLIC_KEY_LEN..ONION_V3_PUBLIC_KEY_LEN + 2] != checksum {
            return Err(TorAddressParseError::InvalidChecksum);
        }

        Ok(TorAddress { onion_v3_address })
    }

    pub(crate) fn from_valid_onion_v3_address(onion_v3_address: String) -> Self {
        TorAddress { onion_v3_address }
    }

    pub fn as_str(&self) -> &str {
        &self.onion_v3_address
    }
}

impl AsRef<str> for TorAddress {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for TorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.onion_v3_address.fmt(f)
    }
}

impl FromStr for TorAddress {
    type Err = TorAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl TryFrom<String> for TorAddress {
    type Error = TorAddressParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<TorAddress> for String {
    fn from(value: TorAddress) -> Self {
        value.onion_v3_address
    }
}

impl Serialize for TorAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TorAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_valid_onion_v3_addresses() {
        let address =
            TorAddress::try_new("5JFGYY7CTRJAVPXVKB5RGLWF7GKUO5VOX27HXESCD3VGSFCG2IWFMXQD.ONION")
                .unwrap();

        assert_eq!(
            address.as_str(),
            "5jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwfmxqd.onion"
        );
    }

    #[test]
    fn rejects_invalid_onion_checksum() {
        let err =
            TorAddress::try_new("6jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwfmxqd.onion")
                .unwrap_err();

        assert_eq!(err, TorAddressParseError::InvalidChecksum);
    }
}
