use bitcoin::Psbt;
use cryptography::PublicKey;
use musig2::PubNonce;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBoomletIsoMessage1 {
    withdrawal_psbt: Psbt,
    boomerang_descriptor: String,
    boomlet_boom_musig2_pubkey_share: PublicKey,
    boomlet_public_nonces_collection: Vec<PubNonce>,
}

impl WithdrawalBoomletIsoMessage1 {
    pub fn new(
        withdrawal_psbt: Psbt,
        boomerang_descriptor: String,
        boomlet_boom_musig2_pubkey_share: PublicKey,
        boomlet_public_nonces_collection: Vec<PubNonce>,
    ) -> Self {
        WithdrawalBoomletIsoMessage1 {
            withdrawal_psbt,
            boomerang_descriptor,
            boomlet_boom_musig2_pubkey_share,
            boomlet_public_nonces_collection,
        }
    }

    pub fn into_parts(self) -> (Psbt, String, PublicKey, Vec<PubNonce>) {
        (
            self.withdrawal_psbt,
            self.boomerang_descriptor,
            self.boomlet_boom_musig2_pubkey_share,
            self.boomlet_public_nonces_collection,
        )
    }
}

impl Message for WithdrawalBoomletIsoMessage1 {}
