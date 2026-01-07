use serde::{Deserialize, Serialize};

use crate::{constructs::DuressCheckSpace, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalStOutput3 {
    duress_check_space: DuressCheckSpace,
}

impl WithdrawalStOutput3 {
    pub fn new(duress_check_space: DuressCheckSpace) -> Self {
        WithdrawalStOutput3 { duress_check_space }
    }

    pub fn into_parts(self) -> (DuressCheckSpace,) {
        (self.duress_check_space,)
    }
}

impl Message for WithdrawalStOutput3 {}
