use std::collections::BTreeMap;

use cryptography::{PublicKey, SignedData};
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{InitiatorBoomletData, TxApproval},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWtNisoMessage1 {
    boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection:
        BTreeMap<PublicKey, SignedData<TxApproval>>,
    wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
}

impl WithdrawalWtNisoMessage1 {
    pub fn new(
        boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection: BTreeMap<
            PublicKey,
            SignedData<TxApproval>,
        >,
        wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
    ) -> Self {
        WithdrawalWtNisoMessage1 {
            boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
            wt_tx_approval_signed_by_wt,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        BTreeMap<PublicKey, SignedData<TxApproval>>,
        SignedData<TxApproval<InitiatorBoomletData>>,
    ) {
        (
            self.boomlet_i_tx_approval_signed_by_boomlet_i_self_inclusive_collection,
            self.wt_tx_approval_signed_by_wt,
        )
    }
}

impl Message for WithdrawalWtNisoMessage1 {}
