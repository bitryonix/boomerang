use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::BoomletBackupDone, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupIsoBoomletMessage6 {
    boomlet_backup_done_signed_by_boomletwo: SignedData<BoomletBackupDone>,
}

impl SetupIsoBoomletMessage6 {
    pub fn new(boomlet_backup_done_signed_by_boomletwo: SignedData<BoomletBackupDone>) -> Self {
        SetupIsoBoomletMessage6 {
            boomlet_backup_done_signed_by_boomletwo,
        }
    }

    pub fn into_parts(self) -> (SignedData<BoomletBackupDone>,) {
        (self.boomlet_backup_done_signed_by_boomletwo,)
    }
}

impl Message for SetupIsoBoomletMessage6 {}
