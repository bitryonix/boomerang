use bitcoin::Psbt;
use serde::{Deserialize, Serialize};

use crate::{constructs::PeerId, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoOutput1 {
    withdrawal_psbt: Psbt,
    initiator_peer_id: PeerId,
}

impl WithdrawalNonInitiatorNisoOutput1 {
    pub fn new(withdrawal_psbt: Psbt, initiator_peer_id: PeerId) -> Self {
        WithdrawalNonInitiatorNisoOutput1 {
            withdrawal_psbt,
            initiator_peer_id,
        }
    }

    pub fn into_parts(self) -> (Psbt, PeerId) {
        (self.withdrawal_psbt, self.initiator_peer_id)
    }
}

impl Message for WithdrawalNonInitiatorNisoOutput1 {}
