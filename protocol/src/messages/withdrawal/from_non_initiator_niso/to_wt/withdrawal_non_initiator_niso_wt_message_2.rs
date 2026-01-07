use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::Approvals, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoWtMessage2 {
    approvals_signed_by_boomlet: SignedData<Approvals>,
}

impl WithdrawalNonInitiatorNisoWtMessage2 {
    pub fn new(approvals_signed_by_boomlet: SignedData<Approvals>) -> Self {
        WithdrawalNonInitiatorNisoWtMessage2 {
            approvals_signed_by_boomlet,
        }
    }

    pub fn into_parts(self) -> (SignedData<Approvals>,) {
        (self.approvals_signed_by_boomlet,)
    }
}

impl Message for WithdrawalNonInitiatorNisoWtMessage2 {}
