use std::collections::BTreeMap;

use bitcoin::Psbt;
use cryptography::{PublicKey, SignedData};
use serde::{Deserialize, Serialize};

use crate::{constructs::Ping, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoBoomletMessage8 {
    withdrawal_psbt: Psbt,
    boomlet_i_reached_ping_signed_by_boomlet_i_collection: BTreeMap<PublicKey, SignedData<Ping>>,
}

impl WithdrawalNisoBoomletMessage8 {
    pub fn new(
        withdrawal_psbt: Psbt,
        boomlet_i_reached_ping_signed_by_boomlet_i_collection: BTreeMap<
            PublicKey,
            SignedData<Ping>,
        >,
    ) -> Self {
        WithdrawalNisoBoomletMessage8 {
            withdrawal_psbt,
            boomlet_i_reached_ping_signed_by_boomlet_i_collection,
        }
    }

    pub fn into_parts(self) -> (Psbt, BTreeMap<PublicKey, SignedData<Ping>>) {
        (
            self.withdrawal_psbt,
            self.boomlet_i_reached_ping_signed_by_boomlet_i_collection,
        )
    }
}

impl Message for WithdrawalNisoBoomletMessage8 {}
