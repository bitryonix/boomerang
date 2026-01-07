use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    constructs::{SarId, SarServiceFeePaymentReceipt},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPhoneInput2 {
    sar_service_fee_payment_receipts_collection: BTreeMap<SarId, SarServiceFeePaymentReceipt>,
}

impl SetupPhoneInput2 {
    pub fn new(
        sar_service_fee_payment_receipts_collection: BTreeMap<SarId, SarServiceFeePaymentReceipt>,
    ) -> Self {
        SetupPhoneInput2 {
            sar_service_fee_payment_receipts_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeMap<SarId, SarServiceFeePaymentReceipt>,) {
        (self.sar_service_fee_payment_receipts_collection,)
    }
}

impl Message for SetupPhoneInput2 {}
