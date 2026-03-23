use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoOutput5 {
    magic: String,
}

impl SetupIsoOutput5 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupIsoOutput5 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}
