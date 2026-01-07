use serde::{Deserialize, Serialize};

use crate::{constructs::WtServiceFeePaymentReceipt, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoWtMessage2 {
    wt_service_fee_payment_receipt: WtServiceFeePaymentReceipt,
}

impl SetupNisoWtMessage2 {
    pub fn new(wt_service_fee_payment_receipt: WtServiceFeePaymentReceipt) -> Self {
        SetupNisoWtMessage2 {
            wt_service_fee_payment_receipt,
        }
    }

    pub fn into_parts(self) -> (WtServiceFeePaymentReceipt,) {
        (self.wt_service_fee_payment_receipt,)
    }
}

impl Message for SetupNisoWtMessage2 {}
