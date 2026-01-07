use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    constructs::{PeerAddress, WtIdsCollection},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoInput2 {
    peer_addresses_self_inclusive_collection: BTreeSet<PeerAddress>,
    wt_ids_collection: WtIdsCollection,
    milestone_blocks_collection: Vec<u32>,
}

impl SetupNisoInput2 {
    pub fn new(
        peer_addresses_self_inclusive_collection: BTreeSet<PeerAddress>,
        wt_ids_collection: WtIdsCollection,
        milestone_blocks_collection: Vec<u32>,
    ) -> Self {
        SetupNisoInput2 {
            peer_addresses_self_inclusive_collection,
            wt_ids_collection,
            milestone_blocks_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeSet<PeerAddress>, WtIdsCollection, Vec<u32>) {
        (
            self.peer_addresses_self_inclusive_collection,
            self.wt_ids_collection,
            self.milestone_blocks_collection,
        )
    }
}

impl Message for SetupNisoInput2 {}
