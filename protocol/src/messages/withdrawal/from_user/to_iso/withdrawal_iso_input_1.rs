use bip39::Mnemonic;
use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::{constructs::Passphrase, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalIsoInput1 {
    network: Network,
    mnemonic: Mnemonic,
    passphrase: Option<Passphrase>,
}

impl WithdrawalIsoInput1 {
    pub fn new(network: Network, mnemonic: Mnemonic, passphrase: Option<Passphrase>) -> Self {
        WithdrawalIsoInput1 {
            network,
            mnemonic,
            passphrase,
        }
    }

    pub fn into_parts(self) -> (Network, Mnemonic, Option<Passphrase>) {
        (self.network, self.mnemonic, self.passphrase)
    }
}

impl Message for WithdrawalIsoInput1 {}
