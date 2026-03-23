use getset::Getters;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub trait Message: Clone + Serialize + DeserializeOwned + 'static {}

impl<T> Message for T where T: Clone + Serialize + DeserializeOwned + 'static {}

#[derive(Debug, Clone, Serialize, Deserialize, Getters)]
#[getset(get = "pub with_prefix")]
pub struct MetadataAttachedMessage<MD, MS> {
    metadata: MD,
    message: MS,
}

impl<MD: Clone, MS: Message> MetadataAttachedMessage<MD, MS> {
    pub fn new(metadata: MD, message: MS) -> Self {
        MetadataAttachedMessage { metadata, message }
    }

    pub fn into_parts(self) -> (MD, MS) {
        (self.metadata, self.message)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BranchingMessage2<A, B> {
    First(A),
    Second(B),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BranchingMessage3<A, B, C> {
    First(A),
    Second(B),
    Third(C),
}
