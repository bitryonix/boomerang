use cryptography::{PublicKey, SignedData};
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletNisoMessage5 {
    sorted_boomlet_i_identity_pubkey_signed_by_boomlet: SignedData<Vec<PublicKey>>,
    boomerang_params_fingerprint_signed_by_boomlet: SignedData<[u8; 32]>,
}

impl SetupBoomletNisoMessage5 {
    pub fn new(
        sorted_boomlet_i_identity_pubkey_signed_by_boomlet: SignedData<Vec<PublicKey>>,
        boomerang_params_fingerprint_signed_by_boomlet: SignedData<[u8; 32]>,
    ) -> Self {
        SetupBoomletNisoMessage5 {
            sorted_boomlet_i_identity_pubkey_signed_by_boomlet,
            boomerang_params_fingerprint_signed_by_boomlet,
        }
    }

    pub fn into_parts(self) -> (SignedData<Vec<PublicKey>>, SignedData<[u8; 32]>) {
        (
            self.sorted_boomlet_i_identity_pubkey_signed_by_boomlet,
            self.boomerang_params_fingerprint_signed_by_boomlet,
        )
    }
}

impl Message for SetupBoomletNisoMessage5 {}
