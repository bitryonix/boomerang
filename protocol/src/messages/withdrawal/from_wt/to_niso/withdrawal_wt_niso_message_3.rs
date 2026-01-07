use std::collections::BTreeMap;

use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::{constructs::SarId, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWtNisoMessage3 {
    boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet: SymmetricCiphertext,
    withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet:
        BTreeMap<SarId, SymmetricCiphertext>,
}

impl WithdrawalWtNisoMessage3 {
    pub fn new(
        boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet: SymmetricCiphertext,
        withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet: BTreeMap<
            SarId,
            SymmetricCiphertext,
        >,
    ) -> Self {
        WithdrawalWtNisoMessage3 {
            boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
            withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        }
    }

    pub fn into_parts(self) -> (SymmetricCiphertext, BTreeMap<SarId, SymmetricCiphertext>) {
        (
            self.boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
            self.withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        )
    }
}

impl Message for WithdrawalWtNisoMessage3 {}
