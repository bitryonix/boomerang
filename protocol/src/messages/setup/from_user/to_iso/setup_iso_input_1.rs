use std::collections::BTreeSet;

use bitcoin::Network;

use serde::{Deserialize, Serialize};

use crate::{
    constructs::{Passphrase, Password, SarId},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoInput1 {
    network: Network,
    entropy: Vec<u8>,
    passphrase: Option<Passphrase>,
    doxing_password: Password,
    sar_ids_collection: BTreeSet<SarId>,
}

impl SetupIsoInput1 {
    pub fn new(
        network: Network,
        entropy: Vec<u8>,
        passphrase: Option<Passphrase>,
        doxing_password: Password,
        sar_ids_collection: BTreeSet<SarId>,
    ) -> Self {
        SetupIsoInput1 {
            network,
            entropy,
            passphrase,
            doxing_password,
            sar_ids_collection,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        Network,
        Vec<u8>,
        Option<Passphrase>,
        Password,
        BTreeSet<SarId>,
    ) {
        (
            self.network,
            self.entropy,
            self.passphrase,
            self.doxing_password,
            self.sar_ids_collection,
        )
    }
}

impl Message for SetupIsoInput1 {}
