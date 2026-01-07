use getset::Getters;

pub trait Message: Clone {}

#[derive(Debug, Clone, Getters)]
#[getset(get = "pub with_prefix")]
pub struct MetadataAttachedMessage<MD: Clone, MS: Message> {
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

#[derive(Debug)]
pub enum BranchingMessage2<A, B> {
    First(A),
    Second(B),
}

#[derive(Debug)]
pub enum BranchingMessage3<A, B, C> {
    First(A),
    Second(B),
    Third(C),
}
