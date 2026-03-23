use getset::Getters;
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Getters, PartialEq, Eq, PartialOrd, Ord)]
#[getset(get = "pub with_prefix")]
pub struct WtServiceFeePaymentReceipt {
    receipt: String,
}

impl WtServiceFeePaymentReceipt {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        WtServiceFeePaymentReceipt {
            receipt: Alphanumeric.sample_string(&mut rand::rng(), 32),
        }
    }
}
