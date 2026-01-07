use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupWtNisoMessage2 {
    boomerang_params_fingerprint_signed_by_wt: SignedData<[u8; 32]>,
}

impl SetupWtNisoMessage2 {
    pub fn new(boomerang_params_fingerprint_signed_by_wt: SignedData<[u8; 32]>) -> Self {
        SetupWtNisoMessage2 {
            boomerang_params_fingerprint_signed_by_wt,
        }
    }

    pub fn into_parts(self) -> (SignedData<[u8; 32]>,) {
        (self.boomerang_params_fingerprint_signed_by_wt,)
    }
}

impl Message for SetupWtNisoMessage2 {}
