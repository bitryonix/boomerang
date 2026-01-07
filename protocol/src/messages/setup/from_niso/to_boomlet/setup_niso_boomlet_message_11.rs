use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoBoomletMessage11 {
    magic: String,
}

impl SetupNisoBoomletMessage11 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupNisoBoomletMessage11 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for SetupNisoBoomletMessage11 {}
