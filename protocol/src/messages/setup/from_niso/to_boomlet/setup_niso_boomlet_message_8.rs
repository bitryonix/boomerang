use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoBoomletMessage8 {
    magic: String,
}

impl SetupNisoBoomletMessage8 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupNisoBoomletMessage8 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for SetupNisoBoomletMessage8 {}
