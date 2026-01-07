use std::collections::BTreeMap;

use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{SarId, WtSarSetupResponse},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoBoomletMessage9 {
    doxing_data_identifier_signed_by_sar_encrypted_by_sar_for_boomlet_signed_by_wt_collection:
        BTreeMap<SarId, SignedData<WtSarSetupResponse>>,
}

impl SetupNisoBoomletMessage9 {
    pub fn new(
        doxing_data_identifier_signed_by_sar_encrypted_by_sar_for_boomlet_signed_by_wt_collection: BTreeMap<SarId, SignedData<WtSarSetupResponse>>,
    ) -> Self {
        SetupNisoBoomletMessage9 {
            doxing_data_identifier_signed_by_sar_encrypted_by_sar_for_boomlet_signed_by_wt_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeMap<SarId, SignedData<WtSarSetupResponse>>,) {
        (
            self.doxing_data_identifier_signed_by_sar_encrypted_by_sar_for_boomlet_signed_by_wt_collection,
        )
    }
}

impl Message for SetupNisoBoomletMessage9 {}
