use bitcoin::Psbt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoInput1 {
    withdrawal_psbt: Psbt,
}

impl WithdrawalNisoInput1 {
    pub fn new(withdrawal_psbt: Psbt) -> Self {
        WithdrawalNisoInput1 { withdrawal_psbt }
    }

    pub fn into_parts(self) -> (Psbt,) {
        (self.withdrawal_psbt,)
    }
}
