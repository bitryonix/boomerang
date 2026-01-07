use bitcoin::key::rand::{Rng, thread_rng};
use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Getters)]
#[getset(get = "pub with_prefix")]
pub struct StCheckWithNonce<T: PartialEq + Eq> {
    content: T,
    nonce: [u8; 32],
}

impl<T: PartialEq + Eq> StCheckWithNonce<T> {
    pub fn new(content: T) -> Self {
        let mut rng = thread_rng();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce);
        StCheckWithNonce { content, nonce }
    }
}
