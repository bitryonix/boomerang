use serde::{Deserialize, Serialize};

use crate::{constructs::WtServiceFeePaymentInfo, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupNisoOutput1 {
    wt_service_fee_payment_info_collection: WtServiceFeePaymentInfo,
}

impl SetupNisoOutput1 {
    pub fn new(wt_service_fee_payment_info_collection: WtServiceFeePaymentInfo) -> Self {
        SetupNisoOutput1 {
            wt_service_fee_payment_info_collection,
        }
    }

    pub fn into_parts(self) -> (WtServiceFeePaymentInfo,) {
        (self.wt_service_fee_payment_info_collection,)
    }
}

impl Message for SetupNisoOutput1 {}
