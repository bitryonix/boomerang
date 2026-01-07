use bip39::Mnemonic;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoOutput1 {
    mnemonic: Mnemonic,
}

impl SetupIsoOutput1 {
    pub fn new(mnemonic: Mnemonic) -> Self {
        SetupIsoOutput1 { mnemonic }
    }

    pub fn into_parts(self) -> (Mnemonic,) {
        (self.mnemonic,)
    }
}

impl Message for SetupIsoOutput1 {}
