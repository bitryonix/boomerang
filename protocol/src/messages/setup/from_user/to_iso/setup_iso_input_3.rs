use bip39::Mnemonic;
use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{Passphrase, Password, StaticDoxingData},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoInput3 {
    network: Network,
    mnemonic: Mnemonic,
    passphrase: Option<Passphrase>,
    milestone_blocks_collection: Vec<u32>,
    static_doxing_data: StaticDoxingData,
    doxing_password: Password,
}

impl SetupIsoInput3 {
    #[allow(clippy::new_without_default)]
    pub fn new(
        network: Network,
        mnemonic: Mnemonic,
        passphrase: Option<Passphrase>,
        milestone_blocks_collection: Vec<u32>,
        static_doxing_data: StaticDoxingData,
        doxing_password: Password,
    ) -> Self {
        SetupIsoInput3 {
            network,
            mnemonic,
            passphrase,
            milestone_blocks_collection,
            static_doxing_data,
            doxing_password,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        Network,
        Mnemonic,
        Option<Passphrase>,
        Vec<u32>,
        StaticDoxingData,
        Password,
    ) {
        (
            self.network,
            self.mnemonic,
            self.passphrase,
            self.milestone_blocks_collection,
            self.static_doxing_data,
            self.doxing_password,
        )
    }
}

impl Message for SetupIsoInput3 {}
