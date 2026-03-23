use getset::Getters;
use serde::Serialize;

use crate::constructs::BoomerangParams;

#[derive(Debug, Hash, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct SharedStateBoomerangParams<'a> {
    magic: String,
    boomerang_params: &'a BoomerangParams,
}

impl<'a> SharedStateBoomerangParams<'a> {
    pub fn new(magic: &str, boomerang_params: &'a BoomerangParams) -> Self {
        SharedStateBoomerangParams {
            magic: magic.to_string(),
            boomerang_params,
        }
    }
}
