use bitcoin::{Psbt, absolute};
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoBoomletMessage1 {
    withdrawal_psbt: Psbt,
    niso_event_block_height: absolute::Height,
}

impl WithdrawalNisoBoomletMessage1 {
    pub fn new(withdrawal_psbt: Psbt, niso_event_block_height: absolute::Height) -> Self {
        WithdrawalNisoBoomletMessage1 {
            withdrawal_psbt,
            niso_event_block_height,
        }
    }

    pub fn into_parts(self) -> (Psbt, absolute::Height) {
        (self.withdrawal_psbt, self.niso_event_block_height)
    }
}

impl Message for WithdrawalNisoBoomletMessage1 {}
