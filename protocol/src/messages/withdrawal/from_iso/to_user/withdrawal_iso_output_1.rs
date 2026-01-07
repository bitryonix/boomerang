use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalIsoOutput1 {
    magic: String,
}

impl WithdrawalIsoOutput1 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        WithdrawalIsoOutput1 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for WithdrawalIsoOutput1 {}
