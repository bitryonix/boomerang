use std::collections::BTreeSet;

use bip39::Mnemonic;
use bitcoin::{
    Network, Psbt,
    bip32::{Xpriv, Xpub},
};
use cryptography::{PrivateKey, PublicKey, SignedData, SymmetricCiphertext, SymmetricKey};
use miniscript::psbt::PsbtSighashMsg;
use musig2::{AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce};
use protocol::constructs::{
    BoomerangParams, BoomletBackupDone, BoomletBackupRequest, Passphrase, Password, SarId,
    StaticDoxingData,
};

pub const TRACING_ACTOR: &str = "ISO";
pub const TRACING_FIELD_LAYER_PROTOCOL: &str = "protocol";
pub const TRACING_FIELD_CEREMONY_SETUP: &str = "setup";
pub const TRACING_FIELD_CEREMONY_WITHDRAWAL: &str = "withdrawal";

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // Setup
    Setup_AfterCreation_BlankSlate,
    Setup_AfterSetupIsoInput1_SetupInitialized,
    Setup_AfterSetupBoomletIsoMessage1_SetupDuressInitialized,
    Setup_AfterSetupStIsoMessage1_SetupStIdentityPubkeyReceived,
    Setup_AfterSetupBoomletIsoMessage2_SetupEncryptedInitialDuressRequestReceived,
    Setup_AfterSetupStIsoMessage2_SetupEncryptedInitialDuressResponseReceived,
    Setup_AfterSetupBoomletIsoMessage3_SetupEncryptedTestDuressRequestReceived,
    Setup_AfterSetupStIsoMessage3_SetupEncryptedTestDuressResponseReceived,
    Setup_AfterSetupBoomletIsoMessage4_SetupDuressFinished,
    Setup_AfterSetupIsoInput2_SetupBackupStarted,
    Setup_AfterSetupBoomletwoIsoMessage1_SetupBoomletwoIdentityPubkeyReceived,
    Setup_AfterSetupIsoInput3_SetupConnectedToBoomletToGiveBoomletwoPubkey,
    Setup_AfterSetupBoomletIsoMessage5_SetupBoomletBackupDataReceived,
    Setup_AfterSetupIsoInput4_SetupConnectedToBoomletwoToGiveBackupData,
    Setup_AfterSetupBoomletwoIsoMessage2_SetupBoomletBackupDone,
    Setup_AfterSetupIsoInput5_SetupConnectedToBoomletToGiveBoomletwoBackupCompletion,
    Setup_AfterSetupBoomletIsoMessage6_SetupBoomletBackupCompleted,
    // Withdrawal
    Withdrawal_AfterWithdrawalIsoInput1_WithdrawalInitialized,
    Withdrawal_AfterWithdrawalBoomletIsoMessage1_WithdrawalBoomletSigningDataReceived,
    Withdrawal_AfterWithdrawalBoomletIsoMessage2_WithdrawalPsbtSignatureCreated,
}

#[derive(Debug)]
pub struct Iso {
    // Main Fields
    pub(super) state: State,
    pub(super) network: Option<Network>,
    pub(super) mnemonic: Option<Mnemonic>,
    pub(super) passphrase: Option<Passphrase>,
    pub(super) master_xpriv: Option<Xpriv>,
    pub(super) purpose_root_xpriv: Option<Xpriv>,
    pub(super) purpose_root_xpub: Option<Xpub>,
    pub(super) normal_privkey: Option<PrivateKey>,
    pub(super) normal_pubkey: Option<PublicKey>,
    pub(super) doxing_password: Option<Password>,
    pub(super) doxing_key: Option<SymmetricKey>,
    pub(super) static_doxing_data: Option<StaticDoxingData>,
    pub(super) milestone_blocks_collection: Option<Vec<u32>>,
    pub(super) sar_ids_collection: Option<BTreeSet<SarId>>,
    pub(super) boomlet_identity_pubkey: Option<PublicKey>,
    pub(super) st_identity_pubkey: Option<PublicKey>,
    pub(super) withdrawal_psbt: Option<Psbt>,
    pub(super) boomerang_descriptor_string: Option<String>,
    pub(super) boomlet_boom_musig2_pubkey_share: Option<PublicKey>,
    pub(super) boom_pubkey: Option<PublicKey>,
    pub(super) boomlet_public_nonces_collection: Option<Vec<PubNonce>>,
    pub(super) withdrawal_public_nonces_collection: Option<Vec<PubNonce>>,
    pub(super) withdrawal_secret_nonces_collection: Option<Vec<SecNonce>>,
    pub(super) withdrawal_sighashes_collection: Option<Vec<PsbtSighashMsg>>,
    pub(super) withdrawal_aggregated_nonces_collection: Option<Vec<AggNonce>>,
    pub(super) withdrawal_partial_signatures_collection: Option<Vec<PartialSignature>>,
    pub(super) withdrawal_final_tap_signatures_collection: Option<Vec<bitcoin::taproot::Signature>>,
    // Transient Fields
    pub(super) boomletwo_identity_pubkey: Option<PublicKey>,
    pub(super) boomlet_backup_request_signed_by_normal_key:
        Option<SignedData<BoomletBackupRequest>>,
    pub(super) boomlet_backup_encrypted_by_boomlet_for_boomletwo: Option<SymmetricCiphertext>,
    pub(super) boomerang_params: Option<BoomerangParams>,
    pub(super) duress_check_space_with_nonce_encrypted_by_boomlet_for_st:
        Option<SymmetricCiphertext>,
    pub(super) duress_signal_index_with_nonce_encrypted_by_st_for_boomlet:
        Option<SymmetricCiphertext>,
    pub(super) boomlet_backup_done_signed_by_boomletwo: Option<SignedData<BoomletBackupDone>>,
    // Internal Fields
    pub(super) withdrawal_key_agg_context: Option<KeyAggContext>,
}

impl Iso {
    pub fn create() -> Self {
        Iso {
            // Main Fields
            state: State::Setup_AfterCreation_BlankSlate,
            network: None,
            mnemonic: None,
            passphrase: None,
            master_xpriv: None,
            purpose_root_xpriv: None,
            purpose_root_xpub: None,
            normal_privkey: None,
            normal_pubkey: None,
            doxing_password: None,
            doxing_key: None,
            static_doxing_data: None,
            milestone_blocks_collection: None,
            sar_ids_collection: None,
            boomlet_identity_pubkey: None,
            st_identity_pubkey: None,
            withdrawal_psbt: None,
            boomerang_descriptor_string: None,
            boomlet_boom_musig2_pubkey_share: None,
            boom_pubkey: None,
            boomlet_public_nonces_collection: None,
            withdrawal_public_nonces_collection: None,
            withdrawal_secret_nonces_collection: None,
            withdrawal_sighashes_collection: None,
            withdrawal_aggregated_nonces_collection: None,
            withdrawal_partial_signatures_collection: None,
            withdrawal_final_tap_signatures_collection: None,
            // Transient Fields
            boomletwo_identity_pubkey: None,
            boomlet_backup_request_signed_by_normal_key: None,
            boomlet_backup_encrypted_by_boomlet_for_boomletwo: None,
            boomerang_params: None,
            duress_check_space_with_nonce_encrypted_by_boomlet_for_st: None,
            duress_signal_index_with_nonce_encrypted_by_st_for_boomlet: None,
            boomlet_backup_done_signed_by_boomletwo: None,
            // Internal Fields
            withdrawal_key_agg_context: None,
        }
    }

    pub fn reset_state(&mut self) {
        *self = Iso::create();
    }
}
