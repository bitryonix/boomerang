use bitcoin::Psbt;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBoomletNisoMessage9 {
    withdrawal_psbt: Psbt,
}

impl WithdrawalBoomletNisoMessage9 {
    pub fn new(withdrawal_psbt: Psbt) -> Self {
        WithdrawalBoomletNisoMessage9 { withdrawal_psbt }
    }

    pub fn into_parts(self) -> (Psbt,) {
        (self.withdrawal_psbt,)
    }
}

impl Message for WithdrawalBoomletNisoMessage9 {}
