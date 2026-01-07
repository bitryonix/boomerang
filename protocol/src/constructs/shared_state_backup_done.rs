use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Hash, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct SharedStateBackupDone {
    magic: String,
}

impl SharedStateBackupDone {
    pub fn new(magic: &str) -> Self {
        SharedStateBackupDone {
            magic: magic.to_string(),
        }
    }
}
