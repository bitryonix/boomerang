use std::collections::BTreeMap;

use cryptography::{PublicKey, SignedData};
use serde::{Deserialize, Serialize};

use crate::{constructs::TxApproval, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWtNonInitiatorNisoMessage2 {
    boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection:
        BTreeMap<PublicKey, SignedData<TxApproval>>,
}

impl WithdrawalWtNonInitiatorNisoMessage2 {
    pub fn new(
        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection: BTreeMap<PublicKey, SignedData<TxApproval>>,
    ) -> Self {
        WithdrawalWtNonInitiatorNisoMessage2 {
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeMap<PublicKey, SignedData<TxApproval>>,) {
        (
            self.boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection,
        )
    }
}

impl Message for WithdrawalWtNonInitiatorNisoMessage2 {}
