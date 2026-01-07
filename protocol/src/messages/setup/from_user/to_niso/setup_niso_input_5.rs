use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoInput5 {
    magic: String,
}

impl SetupNisoInput5 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: String) -> Self {
        SetupNisoInput5 { magic }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for SetupNisoInput5 {}
