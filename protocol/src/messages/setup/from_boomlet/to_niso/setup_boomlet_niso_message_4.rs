use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletNisoMessage4 {
    magic: String,
}

impl SetupBoomletNisoMessage4 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupBoomletNisoMessage4 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for SetupBoomletNisoMessage4 {}
