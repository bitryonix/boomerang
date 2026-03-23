use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalBoomletNisoMessage8 {
    magic: String,
}

impl WithdrawalBoomletNisoMessage8 {
    #[allow(clippy::new_without_default)]
    pub fn new(magic: &str) -> Self {
        WithdrawalBoomletNisoMessage8 {
            magic: magic.to_string(),
        }
    }

    pub fn into_parts(self) -> (String,) {
        (self.magic,)
    }
}
