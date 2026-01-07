use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalIsoBoomletMessage2 {
    withdrawal_public_nonces_collection: Vec<PubNonce>,
    withdrawal_partial_signatures_collection: Vec<PartialSignature>,
}

impl WithdrawalIsoBoomletMessage2 {
    pub fn new(
        withdrawal_public_nonces_collection: Vec<PubNonce>,
        withdrawal_partial_signatures_collection: Vec<PartialSignature>,
    ) -> Self {
        WithdrawalIsoBoomletMessage2 {
            withdrawal_public_nonces_collection,
            withdrawal_partial_signatures_collection,
        }
    }

    pub fn into_parts(self) -> (Vec<PubNonce>, Vec<PartialSignature>) {
        (
            self.withdrawal_public_nonces_collection,
            self.withdrawal_partial_signatures_collection,
        )
    }
}

impl Message for WithdrawalIsoBoomletMessage2 {}
