use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPhoneOutput2 {
    magic: String,
}

impl SetupPhoneOutput2 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupPhoneOutput2 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for SetupPhoneOutput2 {}
