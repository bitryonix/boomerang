use serde::{Deserialize, Serialize};

use crate::{constructs::BoomerangParamsSeed, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStOutput4 {
    boomerang_params_seed: BoomerangParamsSeed,
}

impl SetupStOutput4 {
    pub fn new(boomerang_params_seed: BoomerangParamsSeed) -> Self {
        SetupStOutput4 {
            boomerang_params_seed,
        }
    }

    pub fn into_parts(self) -> (BoomerangParamsSeed,) {
        (self.boomerang_params_seed,)
    }
}

impl Message for SetupStOutput4 {}
