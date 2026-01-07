use serde::{Deserialize, Serialize};

use crate::{constructs::WtServiceFeePaymentInfo, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupWtNisoMessage1 {
    wt_service_fee_payment_info: WtServiceFeePaymentInfo,
}

impl SetupWtNisoMessage1 {
    pub fn new(wt_service_fee_payment_info: WtServiceFeePaymentInfo) -> Self {
        SetupWtNisoMessage1 {
            wt_service_fee_payment_info,
        }
    }

    pub fn into_parts(self) -> (WtServiceFeePaymentInfo,) {
        (self.wt_service_fee_payment_info,)
    }
}

impl Message for SetupWtNisoMessage1 {}
