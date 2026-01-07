use std::collections::BTreeMap;

use cryptography::{PublicKey, SignedData, SymmetricCiphertext};
use serde::{Deserialize, Serialize};

use crate::{
    constructs::{SarId, TxCommit},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWtNisoMessage2 {
    boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection:
        BTreeMap<PublicKey, SignedData<SignedData<TxCommit>>>,
    withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet:
        BTreeMap<SarId, SymmetricCiphertext>,
}

impl WithdrawalWtNisoMessage2 {
    pub fn new(
        boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection: BTreeMap<
            PublicKey,
            SignedData<SignedData<TxCommit>>,
        >,
        withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet: BTreeMap<
            SarId,
            SymmetricCiphertext,
        >,
    ) -> Self {
        WithdrawalWtNisoMessage2 {
            boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
            withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        }
    }
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        BTreeMap<PublicKey, SignedData<SignedData<TxCommit>>>,
        BTreeMap<SarId, SymmetricCiphertext>,
    ) {
        (
            self.boomlet_i_tx_commit_signed_by_boomlet_signed_by_wt_self_inclusive_collection,
            self.withdrawal_duress_placeholder_signed_by_sar_encrypted_by_sar_for_boomlet,
        )
    }
}

impl Message for WithdrawalWtNisoMessage2 {}
