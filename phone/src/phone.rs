use std::collections::{BTreeMap, BTreeSet};

use cryptography::SymmetricKey;
use protocol::constructs::{
    DynamicDoxingData, SarId, SarServiceFeePaymentInfo, SarServiceFeePaymentReceipt,
    StaticDoxingData,
};

pub const TRACING_ACTOR: &str = "Phone";
pub const TRACING_FIELD_LAYER_PROTOCOL: &str = "protocol";
pub const TRACING_FIELD_CEREMONY_SETUP: &str = "setup";

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // Setup
    Setup_AfterCreation_BlankSlate,
    Setup_AfterSetupPhoneInput1_SarRegistrationInitialized,
    Setup_AfterSetupSarPhoneMessage1_SarInvoiceReceived,
    Setup_AfterSetupPhoneInput2_SarInvoicePaid,
    Setup_AfterSetupSarPhoneMessage2_SarRegisteredAndConnectedToPhone,
    // Withdrawal
}

#[derive(Debug)]
pub struct Phone {
    // Main Fields
    pub(super) state: State,
    pub(super) doxing_key: Option<SymmetricKey>,
    pub(super) sar_ids_collection: Option<BTreeSet<SarId>>,
    pub(super) static_doxing_data: Option<StaticDoxingData>,
    pub(super) dynamic_doxing_data: Option<DynamicDoxingData>,
    pub(super) doxing_data_identifier: Option<[u8; 32]>,
    // Transient Fields
    pub(super) sar_service_fee_payment_info_collection:
        Option<BTreeMap<SarId, SarServiceFeePaymentInfo>>,
    pub(super) sar_service_fee_payment_receipts_collection:
        Option<BTreeMap<SarId, SarServiceFeePaymentReceipt>>,
    // Internal Fields
}

impl Phone {
    pub fn create() -> Self {
        Phone {
            // Main Fields
            state: State::Setup_AfterCreation_BlankSlate,
            doxing_key: None,
            sar_ids_collection: None,
            static_doxing_data: None,
            dynamic_doxing_data: None,
            doxing_data_identifier: None,
            // Transient Fields
            sar_service_fee_payment_info_collection: None,
            sar_service_fee_payment_receipts_collection: None,
            // Internal Fields
        }
    }
}
