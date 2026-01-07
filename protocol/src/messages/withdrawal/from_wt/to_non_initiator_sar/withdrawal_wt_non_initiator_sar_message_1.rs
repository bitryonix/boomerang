use cryptography::PublicKey;
use serde::{Deserialize, Serialize};

use crate::{constructs::DuressPlaceholder, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWtNonInitiatorSarMessage1 {
    boomlet_pubkey: PublicKey,
    duress_placeholder: DuressPlaceholder,
}

impl WithdrawalWtNonInitiatorSarMessage1 {
    pub fn new(boomlet_pubkey: PublicKey, duress_placeholder: DuressPlaceholder) -> Self {
        WithdrawalWtNonInitiatorSarMessage1 {
            boomlet_pubkey,
            duress_placeholder,
        }
    }

    pub fn into_parts(self) -> (PublicKey, DuressPlaceholder) {
        (self.boomlet_pubkey, self.duress_placeholder)
    }
}

impl Message for WithdrawalWtNonInitiatorSarMessage1 {}
