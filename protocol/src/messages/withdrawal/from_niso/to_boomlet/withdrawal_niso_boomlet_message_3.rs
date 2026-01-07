use std::collections::BTreeMap;

use bitcoin::absolute;
use cryptography::{PublicKey, SignedData};
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{InitiatorBoomletData, TxApproval},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoBoomletMessage3 {
    boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection:
        BTreeMap<PublicKey, SignedData<TxApproval>>,
    wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
    niso_event_block_height: absolute::Height,
}

impl WithdrawalNisoBoomletMessage3 {
    pub fn new(
        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection: BTreeMap<
            PublicKey,
            SignedData<TxApproval>,
        >,
        wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
        niso_event_block_height: absolute::Height,
    ) -> Self {
        WithdrawalNisoBoomletMessage3 {
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
            wt_tx_approval_signed_by_wt,
            niso_event_block_height,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        BTreeMap<PublicKey, SignedData<TxApproval>>,
        SignedData<TxApproval<InitiatorBoomletData>>,
        absolute::Height,
    ) {
        (
            self.boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
            self.wt_tx_approval_signed_by_wt,
            self.niso_event_block_height,
        )
    }
}

impl Message for WithdrawalNisoBoomletMessage3 {}
