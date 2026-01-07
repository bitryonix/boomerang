use cryptography::{PublicKey, SignedData};
use serde::{Deserialize, Serialize};

use crate::{constructs::TorAddress, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoWtMessage1 {
    boomlet_identity_pubkey: PublicKey,
    sorted_boomlet_i_identity_pubkey_signed_by_boomlet: SignedData<Vec<PublicKey>>,
    niso_tor_address_signed_by_boomlet: SignedData<TorAddress>,
    boomerang_params_fingerprint_signed_by_boomlet: SignedData<[u8; 32]>,
}

impl SetupNisoWtMessage1 {
    pub fn new(
        boomlet_identity_pubkey: PublicKey,
        sorted_boomlet_i_identity_pubkey_signed_by_boomlet: SignedData<Vec<PublicKey>>,
        niso_tor_address_signed_by_boomlet: SignedData<TorAddress>,
        boomerang_params_fingerprint_signed_by_boomlet: SignedData<[u8; 32]>,
    ) -> Self {
        SetupNisoWtMessage1 {
            boomlet_identity_pubkey,
            sorted_boomlet_i_identity_pubkey_signed_by_boomlet,
            niso_tor_address_signed_by_boomlet,
            boomerang_params_fingerprint_signed_by_boomlet,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        PublicKey,
        SignedData<Vec<PublicKey>>,
        SignedData<TorAddress>,
        SignedData<[u8; 32]>,
    ) {
        (
            self.boomlet_identity_pubkey,
            self.sorted_boomlet_i_identity_pubkey_signed_by_boomlet,
            self.niso_tor_address_signed_by_boomlet,
            self.boomerang_params_fingerprint_signed_by_boomlet,
        )
    }
}

impl Message for SetupNisoWtMessage1 {}
