use std::collections::BTreeSet;

use bitcoin::Network;
use cryptography::{PublicKey, SymmetricKey};
use serde::{Deserialize, Serialize};

use crate::{constructs::SarId, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoBoomletMessage1 {
    network: Network,
    normal_pubkey: PublicKey,
    doxing_key: SymmetricKey,
    sar_ids_collection: BTreeSet<SarId>,
}

impl SetupIsoBoomletMessage1 {
    pub fn new(
        network: Network,
        normal_pubkey: PublicKey,
        doxing_key: SymmetricKey,
        sar_ids_collection: BTreeSet<SarId>,
    ) -> Self {
        SetupIsoBoomletMessage1 {
            network,
            normal_pubkey,
            doxing_key,
            sar_ids_collection,
        }
    }

    pub fn into_parts(self) -> (Network, PublicKey, SymmetricKey, BTreeSet<SarId>) {
        (
            self.network,
            self.normal_pubkey,
            self.doxing_key,
            self.sar_ids_collection,
        )
    }
}

impl Message for SetupIsoBoomletMessage1 {}
