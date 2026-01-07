use cryptography::{SignedData, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{InitiatorBoomletData, TxApproval},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWtNonInitiatorNisoMessage1 {
    wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
    initiator_boomlet_tx_approval_signed_by_initiator_boomlet: SignedData<TxApproval>,
    psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet: SymmetricCiphertext,
}

impl WithdrawalWtNonInitiatorNisoMessage1 {
    pub fn new(
        wt_tx_approval_signed_by_wt: SignedData<TxApproval<InitiatorBoomletData>>,
        initiator_boomlet_tx_approval_signed_by_initiator_boomlet: SignedData<TxApproval>,
        psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet: SymmetricCiphertext,
    ) -> Self {
        WithdrawalWtNonInitiatorNisoMessage1 {
            wt_tx_approval_signed_by_wt,
            initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        SignedData<TxApproval<InitiatorBoomletData>>,
        SignedData<TxApproval>,
        SymmetricCiphertext,
    ) {
        (
            self.wt_tx_approval_signed_by_wt,
            self.initiator_boomlet_tx_approval_signed_by_initiator_boomlet,
            self.psbt_encrypted_by_initiator_boomlet_for_non_initiator_boomlet,
        )
    }
}

impl Message for WithdrawalWtNonInitiatorNisoMessage1 {}
