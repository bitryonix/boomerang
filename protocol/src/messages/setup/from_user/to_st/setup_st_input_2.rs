use serde::{Deserialize, Serialize};

use crate::{constructs::DuressSignalIndex, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStInput2 {
    duress_signal_index: DuressSignalIndex,
}

impl SetupStInput2 {
    pub fn new(duress_signal_index: DuressSignalIndex) -> Self {
        SetupStInput2 {
            duress_signal_index,
        }
    }

    pub fn into_parts(self) -> (DuressSignalIndex,) {
        (self.duress_signal_index,)
    }
}

impl Message for SetupStInput2 {}
