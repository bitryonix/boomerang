use getset::Getters;
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Getters, PartialEq, Eq, PartialOrd, Ord)]
#[getset(get = "pub with_prefix")]
pub struct StaticDoxingData {
    name: String,
    home_address: String,
    work_address: String,
    phone_1: String,
    phone_2: String,
    family_members: String,
    family_contact_info: String,
}

impl StaticDoxingData {
    pub fn new(
        name: String,
        home_address: String,
        work_address: String,
        phone_1: String,
        phone_2: String,
        family_members: String,
        family_contact_info: String,
    ) -> Self {
        StaticDoxingData {
            name,
            home_address,
            work_address,
            phone_1,
            phone_2,
            family_members,
            family_contact_info,
        }
    }

    pub fn new_random() -> Self {
        let name = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let home_address = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let work_address = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let phone_1 = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let phone_2 = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let family_members = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let family_contact_info = Alphanumeric.sample_string(&mut rand::rng(), 32);
        StaticDoxingData {
            name,
            home_address,
            work_address,
            phone_1,
            phone_2,
            family_members,
            family_contact_info,
        }
    }
}
