use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoOutput3 {
    magic: String,
}

impl SetupNisoOutput3 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupNisoOutput3 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for SetupNisoOutput3 {}
