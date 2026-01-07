use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::BoomletBackupRequest, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoBoomletMessage5 {
    boomlet_backup_request_signed_by_normal_key: SignedData<BoomletBackupRequest>,
}

impl SetupIsoBoomletMessage5 {
    pub fn new(
        boomlet_backup_request_signed_by_normal_key: SignedData<BoomletBackupRequest>,
    ) -> Self {
        SetupIsoBoomletMessage5 {
            boomlet_backup_request_signed_by_normal_key,
        }
    }

    pub fn into_parts(self) -> (SignedData<BoomletBackupRequest>,) {
        (self.boomlet_backup_request_signed_by_normal_key,)
    }
}

impl Message for SetupIsoBoomletMessage5 {}
