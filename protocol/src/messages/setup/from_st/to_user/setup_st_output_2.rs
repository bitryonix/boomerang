use serde::{Deserialize, Serialize};

use crate::{constructs::DuressCheckSpace, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStOutput2 {
    duress_check_space: DuressCheckSpace,
}

impl SetupStOutput2 {
    pub fn new(duress_check_space: DuressCheckSpace) -> Self {
        SetupStOutput2 { duress_check_space }
    }

    pub fn into_parts(self) -> (DuressCheckSpace,) {
        (self.duress_check_space,)
    }
}

impl Message for SetupStOutput2 {}
