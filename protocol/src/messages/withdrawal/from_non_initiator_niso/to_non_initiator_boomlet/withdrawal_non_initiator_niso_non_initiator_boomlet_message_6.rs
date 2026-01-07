use bitcoin::absolute;
use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::TxCommit, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6 {
    initiator_boomlet_tx_commit_signed_by_boomlet_signed_by_wt: SignedData<SignedData<TxCommit>>,
    niso_event_block_height: absolute::Height,
}

impl WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6 {
    pub fn new(
        initiator_boomlet_tx_commit_signed_by_boomlet_signed_by_wt: SignedData<
            SignedData<TxCommit>,
        >,
        niso_event_block_height: absolute::Height,
    ) -> Self {
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6 {
            initiator_boomlet_tx_commit_signed_by_boomlet_signed_by_wt,
            niso_event_block_height,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(self) -> (SignedData<SignedData<TxCommit>>, absolute::Height) {
        (
            self.initiator_boomlet_tx_commit_signed_by_boomlet_signed_by_wt,
            self.niso_event_block_height,
        )
    }
}

impl Message for WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6 {}
