use std::collections::BTreeMap;

use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{SarId, WtSarSetupResponse},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupWtNisoMessage3 {
    sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection:
        BTreeMap<SarId, SignedData<WtSarSetupResponse>>,
}

impl SetupWtNisoMessage3 {
    pub fn new(
        sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection: BTreeMap<SarId, SignedData<WtSarSetupResponse>>,
    ) -> Self {
        SetupWtNisoMessage3 {
            sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeMap<SarId, SignedData<WtSarSetupResponse>>,) {
        (
            self.sar_setup_response_signed_by_sar_encrypted_by_sar_for_boomlet_suffixed_by_wt_signed_by_wt_collection,
        )
    }
}

impl Message for SetupWtNisoMessage3 {}
