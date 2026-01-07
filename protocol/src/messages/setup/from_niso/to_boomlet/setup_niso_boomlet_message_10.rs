use std::collections::BTreeMap;

use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::PeerId, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoBoomletMessage10 {
    shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection:
        BTreeMap<PeerId, SignedData<[u8; 32]>>,
}

impl SetupNisoBoomletMessage10 {
    pub fn new(
        shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection: BTreeMap<
            PeerId,
            SignedData<[u8; 32]>,
        >,
    ) -> Self {
        SetupNisoBoomletMessage10 {
            shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeMap<PeerId, SignedData<[u8; 32]>>,) {
        (self.shared_state_fingerprint_signed_by_boomlet_i_self_exclusive_collection,)
    }
}

impl Message for SetupNisoBoomletMessage10 {}
