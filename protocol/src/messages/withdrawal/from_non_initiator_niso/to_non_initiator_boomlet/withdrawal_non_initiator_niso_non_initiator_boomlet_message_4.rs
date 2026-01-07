use std::collections::BTreeMap;

use bitcoin::absolute;
use cryptography::{PublicKey, SignedData};
use serde::{Deserialize, Serialize};

use crate::{constructs::TxApproval, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4 {
    non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection:
        BTreeMap<PublicKey, SignedData<TxApproval>>,
    niso_event_block_height: absolute::Height,
}

impl WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4 {
    pub fn new(
        non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection: BTreeMap<PublicKey, SignedData<TxApproval>>,
        niso_event_block_height: absolute::Height,
    ) -> Self {
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4 {
            non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection,
            niso_event_block_height,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        BTreeMap<PublicKey, SignedData<TxApproval>>,
        absolute::Height,
    ) {
        (
            self.non_initiator_boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_initiator_exclusive_collection,
            self.niso_event_block_height,
        )
    }
}

impl Message for WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4 {}
