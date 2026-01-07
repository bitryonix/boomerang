use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2 {
    magic: String,
}

impl WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2 {
    pub fn new(magic: &str) -> Self {
        WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2 {}
