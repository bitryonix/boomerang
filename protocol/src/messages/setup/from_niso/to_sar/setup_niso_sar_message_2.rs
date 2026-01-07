use serde::{Deserialize, Serialize};

use crate::{constructs::SarServiceFeePaymentReceipt, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoSarMessage2 {
    sar_service_fee_payment_receipt: SarServiceFeePaymentReceipt,
}

impl SetupNisoSarMessage2 {
    pub fn new(sar_service_fee_payment_receipt: SarServiceFeePaymentReceipt) -> Self {
        SetupNisoSarMessage2 {
            sar_service_fee_payment_receipt,
        }
    }

    pub fn into_parts(self) -> (SarServiceFeePaymentReceipt,) {
        (self.sar_service_fee_payment_receipt,)
    }
}

impl Message for SetupNisoSarMessage2 {}
