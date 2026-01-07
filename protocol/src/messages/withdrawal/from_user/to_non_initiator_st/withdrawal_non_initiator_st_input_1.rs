use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNonInitiatorStInput1 {
    magic: String,
}

impl WithdrawalNonInitiatorStInput1 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        WithdrawalNonInitiatorStInput1 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for WithdrawalNonInitiatorStInput1 {}
