use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::TxCommit, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWtNonInitiatorNisoMessage3 {
    initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt:
        SignedData<SignedData<TxCommit>>,
}

impl WithdrawalWtNonInitiatorNisoMessage3 {
    pub fn new(
        initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt: SignedData<
            SignedData<TxCommit>,
        >,
    ) -> Self {
        WithdrawalWtNonInitiatorNisoMessage3 {
            initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt,
        }
    }

    pub fn into_parts(self) -> (SignedData<SignedData<TxCommit>>,) {
        (self.initiator_boomlet_tx_commit_signed_by_initiator_boomlet_signed_by_wt,)
    }
}

impl Message for WithdrawalWtNonInitiatorNisoMessage3 {}
