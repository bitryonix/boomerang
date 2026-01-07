use musig2::PartialSignature;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBoomletIsoMessage2 {
    withdrawal_partial_signatures_collection: Vec<PartialSignature>,
}

impl WithdrawalBoomletIsoMessage2 {
    pub fn new(withdrawal_partial_signatures_collection: Vec<PartialSignature>) -> Self {
        WithdrawalBoomletIsoMessage2 {
            withdrawal_partial_signatures_collection,
        }
    }

    pub fn into_parts(self) -> (Vec<PartialSignature>,) {
        (self.withdrawal_partial_signatures_collection,)
    }
}

impl Message for WithdrawalBoomletIsoMessage2 {}
