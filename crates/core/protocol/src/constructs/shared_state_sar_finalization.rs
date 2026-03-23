use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Hash, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct SharedStateSarFinalization {
    magic: String,
}

impl SharedStateSarFinalization {
    pub fn new(magic: &str) -> Self {
        SharedStateSarFinalization {
            magic: magic.to_string(),
        }
    }
}
