use std::collections::BTreeSet;

use getset::Getters;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::constructs::{PeerId, WtIdsCollection};

#[derive(Debug, Hash, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct BoomerangParamsSeed {
    self_inclusive_peer_ids_collection: BTreeSet<PeerId>,
    milestone_blocks_collection: Vec<u32>,
    wt_ids_collection: WtIdsCollection,
}

impl BoomerangParamsSeed {
    pub fn new(
        self_inclusive_peer_ids_collection: BTreeSet<PeerId>,
        milestone_blocks_collection: Vec<u32>,
        wt_ids_collection: WtIdsCollection,
    ) -> Self {
        BoomerangParamsSeed {
            self_inclusive_peer_ids_collection,
            milestone_blocks_collection,
            wt_ids_collection,
        }
    }
}

#[derive(Debug, Hash, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct BoomerangParamsSeedWithNonce {
    boomerang_params_seed: BoomerangParamsSeed,
    nonce: [u8; 32],
}

impl BoomerangParamsSeedWithNonce {
    pub fn new(boomerang_params_seed: BoomerangParamsSeed) -> Self {
        let mut rng = rand::rng();
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        BoomerangParamsSeedWithNonce {
            boomerang_params_seed,
            nonce,
        }
    }
}
