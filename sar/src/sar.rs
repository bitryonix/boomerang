use std::collections::BTreeSet;

use cryptography::{PrivateKey, PublicKey, SymmetricCiphertext, SymmetricKey};
use protocol::constructs::{
    DuressPlaceholder, DynamicDoxingData, SarId, SarServiceFeePaymentInfo,
    SarServiceFeePaymentReceipt, StaticDoxingData,
};
use tracing::{Level, instrument};

pub const TRACING_ACTOR: &str = "SAR";
pub const TRACING_FIELD_LAYER_PROTOCOL: &str = "protocol";
pub const TRACING_FIELD_CEREMONY_SETUP: &str = "setup";
pub const TRACING_FIELD_CEREMONY_WITHDRAWAL: &str = "withdrawal";

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // Setup
    Setup_AfterCreation_BlankSlate,
    Setup_AfterLoad_SetupReadyToRegisterService,
    Setup_AfterPhoneSarMessage1_SetupRegistrationInfoReceived,
    Setup_AfterPhoneSarMessage2_SarSetupDoneAndInSyncWithPhone,
    Setup_AfterWtSarMessage1_SetupFinalizationDataReceived,
    // Withdrawal
    Withdrawal_AfterWtSarMessage1_WithdrawalDuressPlaceholderReceived,
    Withdrawal_AfterWtNonInitiatorSarMessage1_WithdrawalDuressPlaceholderReceived,
    Withdrawal_AfterWtSarMessage2_WithdrawalPingDuressPlaceholderReceived,
}

#[derive(Debug)]
pub struct Sar {
    // Main Fields
    pub(super) state: State,
    pub(super) sar_privkey: Option<PrivateKey>,
    pub(super) sar_pubkey: Option<PublicKey>,
    pub(super) sar_id: Option<SarId>,
    pub(super) doxing_data_identifier: Option<[u8; 32]>,
    pub(crate) sar_service_fee_payment_info: Option<SarServiceFeePaymentInfo>,
    pub(crate) sar_service_fee_payment_receipt: Option<SarServiceFeePaymentReceipt>,
    pub(super) static_doxing_data_encrypted_by_doxing_key: Option<SymmetricCiphertext>,
    pub(super) dynamic_doxing_data_encrypted_by_doxing_key: Option<SymmetricCiphertext>,
    pub(super) search_and_rescue_mode: Option<bool>,
    pub(super) static_doxing_data_decrypted: Option<StaticDoxingData>,
    pub(super) dynamic_doxing_data_decrypted: Option<DynamicDoxingData>,
    pub(super) boomlet_identity_pubkey: Option<PublicKey>,
    pub(super) shared_boomlet_sar_symmetric_key: Option<SymmetricKey>,
    pub(super) seen_ivs_collection_for_positive_duress_signals:
        Option<BTreeSet<(PublicKey, [u8; 16])>>,
    // Transient Fields
    pub(super) duress_placeholder: Option<DuressPlaceholder>,
    // Internal Fields
}

impl Sar {
    #[instrument(
        level = Level::DEBUG,
        fields(actor = TRACING_ACTOR, layer = TRACING_FIELD_LAYER_PROTOCOL, ceremony = TRACING_FIELD_CEREMONY_SETUP),
    )]
    pub fn create() -> Self {
        Sar {
            // Main Fields
            state: State::Setup_AfterCreation_BlankSlate,
            sar_privkey: None,
            sar_pubkey: None,
            sar_id: None,
            doxing_data_identifier: None,
            sar_service_fee_payment_info: None,
            sar_service_fee_payment_receipt: None,
            static_doxing_data_encrypted_by_doxing_key: None,
            dynamic_doxing_data_encrypted_by_doxing_key: None,
            search_and_rescue_mode: None,
            static_doxing_data_decrypted: None,
            dynamic_doxing_data_decrypted: None,
            boomlet_identity_pubkey: None,
            shared_boomlet_sar_symmetric_key: None,
            seen_ivs_collection_for_positive_duress_signals: None,
            // Transient Fields
            duress_placeholder: None,
            // Internal Fields
        }
    }

    pub fn get_sar_id(&self) -> Option<SarId> {
        self.sar_id.clone()
    }
}
