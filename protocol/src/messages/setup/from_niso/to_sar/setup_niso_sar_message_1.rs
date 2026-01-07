use cryptography::PublicKey;
use serde::{Deserialize, Serialize};

use crate::{constructs::WtId, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoSarMessage1 {
    boomlet_identity_pubkey: PublicKey,
    wt_ids_collection: Vec<WtId>,
    doxing_data_identifier: [u8; 32],
}

impl SetupNisoSarMessage1 {
    pub fn new(
        boomlet_identity_pubkey: PublicKey,
        wt_ids_collection: Vec<WtId>,
        doxing_data_identifier: [u8; 32],
    ) -> Self {
        SetupNisoSarMessage1 {
            boomlet_identity_pubkey,
            wt_ids_collection,
            doxing_data_identifier,
        }
    }

    pub fn into_parts(self) -> (PublicKey, Vec<WtId>, [u8; 32]) {
        (
            self.boomlet_identity_pubkey,
            self.wt_ids_collection,
            self.doxing_data_identifier,
        )
    }
}

impl Message for SetupNisoSarMessage1 {}
