use cryptography::PublicKey;
use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Getters, Clone, PartialEq)]
#[getset(get = "pub with_prefix")]
pub struct BoomletBackupRequest {
    magic: String,
    boomletwo_identity_pubkey: PublicKey,
    normal_pubkey: PublicKey,
}

impl BoomletBackupRequest {
    pub fn new(
        magic: &str,
        boomletwo_identity_pubkey: PublicKey,
        normal_pubkey: PublicKey,
    ) -> Self {
        BoomletBackupRequest {
            magic: magic.to_string(),
            boomletwo_identity_pubkey,
            normal_pubkey,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(self) -> (String, PublicKey, PublicKey) {
        (
            self.magic,
            self.boomletwo_identity_pubkey,
            self.normal_pubkey,
        )
    }
}
