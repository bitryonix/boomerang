use std::collections::BTreeMap;

use cryptography::{PublicKey, SignedData};
use getset::Getters;
use serde::{Deserialize, Serialize};

use crate::constructs::{InitiatorBoomletData, TxApproval};

#[derive(Debug, Serialize, Deserialize, Clone, Getters, PartialEq)]
#[getset(get = "pub with_prefix")]
pub struct Approvals {
    boomlet_i_tx_approval_signed_by_boomlet_i_collection:
        BTreeMap<PublicKey, SignedData<TxApproval>>,
    wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
}

impl Approvals {
    pub fn new(
        boomlet_i_tx_approval_signed_by_boomlet_i_collection: BTreeMap<
            PublicKey,
            SignedData<TxApproval>,
        >,
        wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
    ) -> Self {
        Approvals {
            boomlet_i_tx_approval_signed_by_boomlet_i_collection,
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
            self.boomlet_i_tx_approval_signed_by_boomlet_i_collection,
            self.wt_tx_approval_signed_by_wt,
        )
    }
}
