use bitcoin::absolute;
use cryptography::{SignedData, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{InitiatorBoomletData, TxApproval},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1 {
    initiator_boomlet_tx_approval_signed_by_initiator_boomlet: SignedData<TxApproval>,
    psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet: SymmetricCiphertext,
    wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
    niso_event_block_height: absolute::Height,
}

impl WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1 {
    pub fn new(
        initiator_boomlet_tx_approval_signed_by_initiator_boomlet: SignedData<TxApproval>,
        psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet: SymmetricCiphertext,
        wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
        niso_event_block_height: absolute::Height,
    ) -> Self {
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1 {
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
            wt_tx_approval_signed_by_wt,
            niso_event_block_height,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        SignedData<TxApproval>,
        SymmetricCiphertext,
        SignedData<TxApproval<InitiatorBoomletData>>,
        absolute::Height,
    ) {
        (
            self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            self.psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
            self.wt_tx_approval_signed_by_wt,
            self.niso_event_block_height,
        )
    }
}

impl Message for WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1 {}
