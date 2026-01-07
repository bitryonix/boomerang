use std::collections::BTreeMap;

use bitcoin::absolute;
use cryptography::SymmetricCiphertext;
use serde::{Deserialize, Serialize};

use crate::{constructs::SarId, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoBoomletMessage6 {
    boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet: SymmetricCiphertext,
    niso_event_block_height: absolute::Height,
    duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet:
        BTreeMap<SarId, SymmetricCiphertext>,
}

impl WithdrawalNisoBoomletMessage6 {
    pub fn new(
        boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet: SymmetricCiphertext,
        niso_event_block_height: absolute::Height,
        duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet: BTreeMap<
            SarId,
            SymmetricCiphertext,
        >,
    ) -> Self {
        WithdrawalNisoBoomletMessage6 {
            boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
            niso_event_block_height,
            duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        SymmetricCiphertext,
        absolute::Height,
        BTreeMap<SarId, SymmetricCiphertext>,
    ) {
        (
            self.boomlet_pong_signed_by_wt_encrypted_by_wt_for_boomlet,
            self.niso_event_block_height,
            self.duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        )
    }
}

impl Message for WithdrawalNisoBoomletMessage6 {}
