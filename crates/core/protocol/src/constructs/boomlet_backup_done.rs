use cryptography::PublicKey;
use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Getters, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[getset(get = "pub with_prefix")]
pub struct BoomletBackupDone {
    magic: String,
    boomletwo_identity_pubkey: PublicKey,
    boomlet_identity_pubkey: PublicKey,
}

impl BoomletBackupDone {
    pub fn new(
        magic: &str,
        boomletwo_identity_pubkey: PublicKey,
        boomlet_identity_pubkey: PublicKey,
    ) -> Self {
        BoomletBackupDone {
            magic: magic.to_string(),
            boomletwo_identity_pubkey,
            boomlet_identity_pubkey,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(self) -> (String, PublicKey, PublicKey) {
        (
            self.magic,
            self.boomletwo_identity_pubkey,
            self.boomlet_identity_pubkey,
        )
    }
}
