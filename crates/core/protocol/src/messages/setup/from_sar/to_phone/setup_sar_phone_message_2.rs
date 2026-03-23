use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupSarPhoneMessage2 {
    magic: String,
}

impl SetupSarPhoneMessage2 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupSarPhoneMessage2 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}
