use std::collections::BTreeMap;

use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::{constructs::SarId, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoWtMessage3 {
    sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
    doxing_data_identifier_encrypted_by_boomlet_for_sars_collection:
        BTreeMap<SarId, SymmetricCiphertext>,
}

impl SetupNisoWtMessage3 {
    pub fn new(
        sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt: SymmetricCiphertext,
        doxing_data_identifier_encrypted_by_boomlet_for_sars_collection: BTreeMap<
            SarId,
            SymmetricCiphertext,
        >,
    ) -> Self {
        SetupNisoWtMessage3 {
            sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext, BTreeMap<SarId, SymmetricCiphertext>) {
        (
            self.sar_ids_collection_signed_by_boomlet_encrypted_by_boomlet_for_wt,
            self.doxing_data_identifier_encrypted_by_boomlet_for_sars_collection,
        )
    }
}

impl Message for SetupNisoWtMessage3 {}
