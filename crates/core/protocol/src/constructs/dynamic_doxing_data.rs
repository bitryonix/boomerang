use bitcoin::key::rand::{Rng, thread_rng};
use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Getters, PartialEq, Eq, PartialOrd, Ord)]
#[getset(get = "pub with_prefix")]
pub struct DynamicDoxingData {
    data: [u8; 32],
}

impl DynamicDoxingData {
    pub fn new_random() -> Self {
        let mut rng = thread_rng();
        let mut data = [0u8; 32];
        rng.fill(&mut data);
        DynamicDoxingData { data }
    }
}
