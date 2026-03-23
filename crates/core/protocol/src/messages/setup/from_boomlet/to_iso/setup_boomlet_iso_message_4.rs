use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletIsoMessage4 {
    magic: String,
}

impl SetupBoomletIsoMessage4 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        SetupBoomletIsoMessage4 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}
