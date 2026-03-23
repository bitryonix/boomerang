use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalIsoBoomletMessage1 {
    magic: String,
}

impl WithdrawalIsoBoomletMessage1 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        WithdrawalIsoBoomletMessage1 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}
