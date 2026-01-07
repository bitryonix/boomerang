use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    constructs::{Password, SarId, StaticDoxingData},
    messages::Message,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPhoneInput1 {
    doxing_password: Password,
    sar_ids_collection: BTreeSet<SarId>,
    static_doxing_data: StaticDoxingData,
}

impl SetupPhoneInput1 {
    pub fn new(
        doxing_password: Password,
        sar_ids_collection: BTreeSet<SarId>,
        static_doxing_data: StaticDoxingData,
    ) -> Self {
        SetupPhoneInput1 {
            doxing_password,
            sar_ids_collection,
            static_doxing_data,
        }
    }

    pub fn into_parts(self) -> (Password, BTreeSet<SarId>, StaticDoxingData) {
        (
            self.doxing_password,
            self.sar_ids_collection,
            self.static_doxing_data,
        )
    }
}

impl Message for SetupPhoneInput1 {}
