use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletNisoMessage7 {
    magic: String,
}

impl SetupBoomletNisoMessage7 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupBoomletNisoMessage7 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}

impl Message for SetupBoomletNisoMessage7 {}
