use getset::Getters;
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Getters, PartialEq, Eq, PartialOrd, Ord)]
#[getset(get = "pub with_prefix")]
pub struct SarServiceFeePaymentReceipt {
    receipt: String,
}

impl SarServiceFeePaymentReceipt {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SarServiceFeePaymentReceipt {
            receipt: Alphanumeric.sample_string(&mut rand::rng(), 32),
        }
    }
}
