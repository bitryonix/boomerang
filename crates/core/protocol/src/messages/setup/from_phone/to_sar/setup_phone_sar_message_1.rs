use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPhoneSarMessage1 {
    doxing_data_identifier: [u8; 32],
}

impl SetupPhoneSarMessage1 {
    pub fn new(doxing_data_identifier: [u8; 32]) -> Self {
        SetupPhoneSarMessage1 {
            doxing_data_identifier,
        }
    }

    pub fn into_parts(self) -> ([u8; 32],) {
        (self.doxing_data_identifier,)
    }
}
