use serde::{Deserialize, Serialize};

use crate::constructs::WtServiceFeePaymentInfo;

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
