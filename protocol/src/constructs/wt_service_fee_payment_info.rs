use getset::Getters;
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};

use crate::constructs::WtId;

#[derive(Debug, Clone, Serialize, Deserialize, Getters, PartialEq, Eq, PartialOrd, Ord)]
#[getset(get = "pub with_prefix")]
pub struct WtServiceFeePaymentInfo {
    bitcoin_lightning_invoice: String,
    payment_deadline_absolute_block: u32,
    wt_id: WtId,
}

impl WtServiceFeePaymentInfo {
    pub fn new(payment_deadline_absolute_block: u32, wt_id: WtId) -> Self {
        let bitcoin_lightning_invoice = Alphanumeric.sample_string(&mut rand::rng(), 32);
        WtServiceFeePaymentInfo {
            bitcoin_lightning_invoice,
            payment_deadline_absolute_block,
            wt_id,
        }
    }
}
