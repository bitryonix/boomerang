use cryptography::{PublicKey, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{BoomerangParams, SarSetupResponse},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletIsoMessage5 {
    boomlet_identity_pubkey: PublicKey,
    boomlet_backup_encrypted_by_boomlet_for_boomletwo: SymmetricCiphertext,
    boomerang_params: BoomerangParams,
    sar_setup_response: SarSetupResponse,
}

impl SetupBoomletIsoMessage5 {
    #[allow(clippy::new_without_default)]
    pub fn new(
        boomlet_identity_pubkey: PublicKey,
        boomlet_backup_encrypted_by_boomlet_for_boomletwo: SymmetricCiphertext,
        boomerang_params: BoomerangParams,
        sar_setup_response: SarSetupResponse,
    ) -> Self {
        SetupBoomletIsoMessage5 {
            boomlet_identity_pubkey,
            boomlet_backup_encrypted_by_boomlet_for_boomletwo,
            boomerang_params,
            sar_setup_response,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        PublicKey,
        SymmetricCiphertext,
        BoomerangParams,
        SarSetupResponse,
    ) {
        (
            self.boomlet_identity_pubkey,
            self.boomlet_backup_encrypted_by_boomlet_for_boomletwo,
            self.boomerang_params,
            self.sar_setup_response,
        )
    }
}

impl Message for SetupBoomletIsoMessage5 {}
