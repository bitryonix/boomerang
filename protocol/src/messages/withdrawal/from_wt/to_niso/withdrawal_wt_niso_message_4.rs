use std::collections::BTreeMap;

use cryptography::{PublicKey, SignedData};
use serde::{Deserialize, Serialize};

use crate::{constructs::Ping, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWtNisoMessage4 {
    boomlet_i_reached_ping_signed_by_boomlet_i_collection: BTreeMap<PublicKey, SignedData<Ping>>,
}

impl WithdrawalWtNisoMessage4 {
    pub fn new(
        boomlet_i_reached_ping_signed_by_boomlet_i_collection: BTreeMap<
            PublicKey,
            SignedData<Ping>,
        >,
    ) -> Self {
        WithdrawalWtNisoMessage4 {
            boomlet_i_reached_ping_signed_by_boomlet_i_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeMap<PublicKey, SignedData<Ping>>,) {
        (self.boomlet_i_reached_ping_signed_by_boomlet_i_collection,)
    }
}

impl Message for WithdrawalWtNisoMessage4 {}
