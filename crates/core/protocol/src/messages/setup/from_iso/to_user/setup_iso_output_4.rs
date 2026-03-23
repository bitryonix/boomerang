use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoOutput4 {
    magic: String,
}

impl SetupIsoOutput4 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupIsoOutput4 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}
