use std::collections::BTreeMap;

use bitcoin::absolute;
use cryptography::{PublicKey, SignedData, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{SarId, TxCommit},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalNisoBoomletMessage5 {
    boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection:
        BTreeMap<PublicKey, SignedData<SignedData<TxCommit>>>,
    niso_event_block_height: absolute::Height,
    duress_placeholders_signed_by_sar_encrypted_by_sar_for_boomlet_collection:
        BTreeMap<SarId, SymmetricCiphertext>,
}

impl WithdrawalNisoBoomletMessage5 {
    pub fn new(
        boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection: BTreeMap<
            PublicKey,
            SignedData<SignedData<TxCommit>>,
        >,
        niso_event_block_height: absolute::Height,
        duress_placeholders_signed_by_sar_encrypted_by_sar_for_boomlet_collection: BTreeMap<
            SarId,
            SymmetricCiphertext,
        >,
    ) -> Self {
        WithdrawalNisoBoomletMessage5 {
            boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
            niso_event_block_height,
            duress_placeholders_signed_by_sar_encrypted_by_sar_for_boomlet_collection,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        BTreeMap<PublicKey, SignedData<SignedData<TxCommit>>>,
        absolute::Height,
        BTreeMap<SarId, SymmetricCiphertext>,
    ) {
        (
            self.boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
            self.niso_event_block_height,
            self.duress_placeholders_signed_by_sar_encrypted_by_sar_for_boomlet_collection,
        )
    }
}

impl Message for WithdrawalNisoBoomletMessage5 {}
