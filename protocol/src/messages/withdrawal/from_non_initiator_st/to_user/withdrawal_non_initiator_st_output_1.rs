use bitcoin::Txid;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorStOutput1 {
    withdrawal_tx_id: Txid,
}

impl WithdrawalNonInitiatorStOutput1 {
    pub fn new(withdrawal_tx_id: Txid) -> Self {
        WithdrawalNonInitiatorStOutput1 { withdrawal_tx_id }
    }

    pub fn into_parts(self) -> (Txid,) {
        (self.withdrawal_tx_id,)
    }
}

impl Message for WithdrawalNonInitiatorStOutput1 {}
