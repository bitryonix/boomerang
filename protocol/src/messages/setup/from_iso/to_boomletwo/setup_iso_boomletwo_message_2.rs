use cryptography::{PublicKey, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoBoomletwoMessage2 {
    boomlet_identity_pubkey: PublicKey,
    boomlet_backup_encrypted_by_boomlet_for_boomletwo: SymmetricCiphertext,
}

impl SetupIsoBoomletwoMessage2 {
    #[allow(clippy::new_without_default)]
    pub fn new(
        boomlet_identity_pubkey: PublicKey,
        boomlet_backup_encrypted_by_boomlet_for_boomletwo: SymmetricCiphertext,
    ) -> Self {
        SetupIsoBoomletwoMessage2 {
            boomlet_identity_pubkey,
            boomlet_backup_encrypted_by_boomlet_for_boomletwo,
        }
    }

    pub fn into_parts(self) -> (PublicKey, SymmetricCiphertext) {
        (
            self.boomlet_identity_pubkey,
            self.boomlet_backup_encrypted_by_boomlet_for_boomletwo,
        )
    }
}

impl Message for SetupIsoBoomletwoMessage2 {}
