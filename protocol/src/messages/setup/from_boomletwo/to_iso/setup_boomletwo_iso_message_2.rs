use cryptography::SignedData;
use serde::{Deserialize, Serialize};

use crate::{constructs::BoomletBackupDone, messages::Message};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupBoomletwoIsoMessage2 {
    boomlet_backup_done_signed_by_boomletwo: SignedData<BoomletBackupDone>,
}

impl SetupBoomletwoIsoMessage2 {
    pub fn new(boomlet_backup_done: SignedData<BoomletBackupDone>) -> Self {
        SetupBoomletwoIsoMessage2 {
            boomlet_backup_done_signed_by_boomletwo: boomlet_backup_done,
        }
    }

    pub fn into_parts(self) -> (SignedData<BoomletBackupDone>,) {
        (self.boomlet_backup_done_signed_by_boomletwo,)
    }
}

impl Message for SetupBoomletwoIsoMessage2 {}
