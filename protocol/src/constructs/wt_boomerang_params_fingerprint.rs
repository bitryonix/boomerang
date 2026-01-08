use getset::Getters;
use serde::{Deserialize, Serialize};

#[derive(Debug, Hash, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct WtBoomerangParamsFingerprint {
    boomerang_params_fingerprint: [u8; 32],
    wt_suffix: String,
}

impl WtBoomerangParamsFingerprint {
    pub fn new(boomerang_params_fingerprint: [u8; 32], wt_suffix: &str) -> Self {
        WtBoomerangParamsFingerprint {
            boomerang_params_fingerprint,
            wt_suffix: wt_suffix.to_string(),
        }
    }
}
