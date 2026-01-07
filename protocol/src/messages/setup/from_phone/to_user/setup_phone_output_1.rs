use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    constructs::{SarId, SarServiceFeePaymentInfo},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPhoneOutput1 {
    sar_service_fee_payment_info_collection: BTreeMap<SarId, SarServiceFeePaymentInfo>,
}

impl SetupPhoneOutput1 {
    pub fn new(
        sar_service_fee_payment_info_collection: BTreeMap<SarId, SarServiceFeePaymentInfo>,
    ) -> Self {
        SetupPhoneOutput1 {
            sar_service_fee_payment_info_collection,
        }
    }

    pub fn into_parts(self) -> (BTreeMap<SarId, SarServiceFeePaymentInfo>,) {
        (self.sar_service_fee_payment_info_collection,)
    }
}

impl Message for SetupPhoneOutput1 {}
