use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStInput3 {
    magic: String,
}

impl SetupStInput3 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupStInput3 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for SetupStInput3 {}
