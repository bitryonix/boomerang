use std::collections::BTreeMap;

use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{BoomerangParams, PeerId},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoBoomletMessage4 {
    boomerang_params_signed_by_boomlet_i_self_exclusive_collection:
        BTreeMap<PeerId, SignedData<BoomerangParams>>,
}

impl SetupNisoBoomletMessage4 {
    pub fn new(
        boomerang_params_signed_by_boomlet_i_self_exclusive_collection: BTreeMap<
            PeerId,
            SignedData<BoomerangParams>,
        >,
    ) -> Self {
        SetupNisoBoomletMessage4 {
            boomerang_params_signed_by_boomlet_i_self_exclusive_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeMap<PeerId, SignedData<BoomerangParams>>,) {
        (self.boomerang_params_signed_by_boomlet_i_self_exclusive_collection,)
    }
}

impl Message for SetupNisoBoomletMessage4 {}
