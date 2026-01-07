use serde::{Deserialize, Serialize};

use crate::{constructs::SarServiceFeePaymentInfo, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupSarPhoneMessage1 {
    sar_service_fee_payment_info: SarServiceFeePaymentInfo,
}

impl SetupSarPhoneMessage1 {
    pub fn new(sar_service_fee_payment_info: SarServiceFeePaymentInfo) -> Self {
        SetupSarPhoneMessage1 {
            sar_service_fee_payment_info,
        }
    }

    pub fn into_parts(self) -> (SarServiceFeePaymentInfo,) {
        (self.sar_service_fee_payment_info,)
    }
}

impl Message for SetupSarPhoneMessage1 {}
