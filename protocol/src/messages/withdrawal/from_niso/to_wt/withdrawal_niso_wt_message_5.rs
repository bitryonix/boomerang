use bitcoin::Psbt;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoWtMessage5 {
    withdrawal_psbt: Psbt,
}

impl WithdrawalNisoWtMessage5 {
    pub fn new(withdrawal_psbt: Psbt) -> Self {
        WithdrawalNisoWtMessage5 { withdrawal_psbt }
    }

    pub fn into_parts(self) -> (Psbt,) {
        (self.withdrawal_psbt,)
    }
}

impl Message for WithdrawalNisoWtMessage5 {}
