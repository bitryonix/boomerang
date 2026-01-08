use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::WtBoomerangParamsFingerprint, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoBoomletMessage6 {
    boomerang_params_fingerprint_suffixed_by_wt_signed_by_wt:
        SignedData<WtBoomerangParamsFingerprint>,
}

impl SetupNisoBoomletMessage6 {
    pub fn new(
        boomerang_params_fingerprint_suffixed_by_wt_signed_by_wt: SignedData<
            WtBoomerangParamsFingerprint,
        >,
    ) -> Self {
        SetupNisoBoomletMessage6 {
            boomerang_params_fingerprint_suffixed_by_wt_signed_by_wt,
        }
    }

    pub fn into_parts(self) -> (SignedData<WtBoomerangParamsFingerprint>,) {
        (self.boomerang_params_fingerprint_suffixed_by_wt_signed_by_wt,)
    }
}

impl Message for SetupNisoBoomletMessage6 {}
