use bitcoin::Txid;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalStOutput1 {
    withdrawal_tx_id: Txid,
}

impl WithdrawalStOutput1 {
    pub fn new(withdrawal_tx_id: Txid) -> Self {
        WithdrawalStOutput1 { withdrawal_tx_id }
    }

    pub fn into_parts(self) -> (Txid,) {
        (self.withdrawal_tx_id,)
    }
}

impl Message for WithdrawalStOutput1 {}
