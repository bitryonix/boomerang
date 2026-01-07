use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::Approvals, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5 {
    approvals_signed_by_boomlet: SignedData<Approvals>,
}

impl WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5 {
    pub fn new(approvals_signed_by_boomlet: SignedData<Approvals>) -> Self {
        WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5 {
            approvals_signed_by_boomlet,
        }
    }

    pub fn into_parts(self) -> (SignedData<Approvals>,) {
        (self.approvals_signed_by_boomlet,)
    }
}

impl Message for WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5 {}
