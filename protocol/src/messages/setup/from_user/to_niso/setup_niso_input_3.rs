use serde::{Deserialize, Serialize};

use crate::{constructs::WtServiceFeePaymentReceipt, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoInput3 {
    wt_service_fee_payment_receipt: WtServiceFeePaymentReceipt,
}

impl SetupNisoInput3 {
    pub fn new(wt_service_fee_payment_receipt: WtServiceFeePaymentReceipt) -> Self {
        SetupNisoInput3 {
            wt_service_fee_payment_receipt,
        }
    }

    pub fn into_parts(self) -> (WtServiceFeePaymentReceipt,) {
        (self.wt_service_fee_payment_receipt,)
    }
}

impl Message for SetupNisoInput3 {}
