use getset::Getters;
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};

use crate::constructs::SarId;

#[derive(Debug, Clone, Serialize, Deserialize, Getters, PartialEq, Eq, PartialOrd, Ord)]
#[getset(get = "pub with_prefix")]
pub struct SarServiceFeePaymentInfo {
    bitcoin_lightning_invoice: String,
    payment_deadline_absolute_block: u32,
    sar_id: SarId,
}

impl SarServiceFeePaymentInfo {
    pub fn new(payment_deadline_absolute_block: u32, sar_id: SarId) -> Self {
        let bitcoin_lightning_invoice = Alphanumeric.sample_string(&mut rand::rng(), 32);
        SarServiceFeePaymentInfo {
            bitcoin_lightning_invoice,
            payment_deadline_absolute_block,
            sar_id,
        }
    }
}
