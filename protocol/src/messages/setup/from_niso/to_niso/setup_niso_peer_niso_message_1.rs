use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::BoomerangParams, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoPeerNisoMessage1 {
    boomerang_params_signed_by_boomlet: SignedData<BoomerangParams>,
}

impl SetupNisoPeerNisoMessage1 {
    pub fn new(boomerang_params_signed_by_boomlet: SignedData<BoomerangParams>) -> Self {
        SetupNisoPeerNisoMessage1 {
            boomerang_params_signed_by_boomlet,
        }
    }

    pub fn into_parts(self) -> (SignedData<BoomerangParams>,) {
        (self.boomerang_params_signed_by_boomlet,)
    }
}

impl Message for SetupNisoPeerNisoMessage1 {}
