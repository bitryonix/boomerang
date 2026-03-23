use cryptography::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletwoIsoMessage1 {
    boomletwo_identity_pubkey: PublicKey,
}

impl SetupBoomletwoIsoMessage1 {
    pub fn new(boomletwo_identity_pubkey: PublicKey) -> Self {
        SetupBoomletwoIsoMessage1 {
            boomletwo_identity_pubkey,
        }
    }

    pub fn into_parts(self) -> (PublicKey,) {
        (self.boomletwo_identity_pubkey,)
    }
}
