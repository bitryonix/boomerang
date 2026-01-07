use std::collections::BTreeSet;

use bitcoin::Network;
use getset::Getters;
use serde::{Deserialize, Serialize};
pub use tracing::{Level, event};

use crate::constructs::{PeerId, WtIdsCollection};

#[derive(Debug, Hash, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct BoomerangParams {
    network: Network,
    peer_ids_collection: BTreeSet<PeerId>,
    milestone_blocks_collection: Vec<u32>,
    wt_ids_collection: WtIdsCollection,
    boomerang_descriptor: String,
}

impl BoomerangParams {
    pub fn new(
        network: Network,
        peer_ids_collection: BTreeSet<PeerId>,
        milestone_blocks_collection: Vec<u32>,
        wt_ids_collection: WtIdsCollection,
        boomerang_descriptor: String,
    ) -> Self {
        BoomerangParams {
            network,
            peer_ids_collection,
            milestone_blocks_collection,
            wt_ids_collection,
            boomerang_descriptor,
        }
    }
}
