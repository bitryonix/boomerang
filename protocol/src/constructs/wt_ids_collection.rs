use std::collections::BTreeSet;

use crate::constructs::WtId;
use derive_more::{Display, Error};
use getset::Getters;
use serde::{Deserialize, Serialize};
use tracing::{Level, event};
use tracing_utils::{error_log, function_finish_log, function_start_log};

#[derive(Debug, Hash, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Getters)]
#[getset(get = "pub with_prefix")]
pub struct WtIdsCollection {
    active_wt: WtId,
    not_active_legitimate_wts: BTreeSet<WtId>,
    retired_wts: BTreeSet<WtId>,
}

impl WtIdsCollection {
    pub fn new(active_wt: WtId, not_active_legitimate_wts: BTreeSet<WtId>) -> Self {
        let retired_wts = BTreeSet::new();
        WtIdsCollection {
            active_wt,
            not_active_legitimate_wts,
            retired_wts,
        }
    }

    pub fn is_this_wt_active(&self, wt_id: &WtId) -> bool {
        wt_id == &self.active_wt
    }

    pub fn retire_current_wt_and_select_another(
        &mut self,
        new_active_wt: WtId,
    ) -> Result<(), WtIdsCollectionError> {
        // Log start.
        function_start_log!();
        // Checks.
        if !self.not_active_legitimate_wts.contains(&new_active_wt) {
            let err = WtIdsCollectionError::NewWtIsNotInTheListOfNotActiveLegitimateWts;
            error_log!(err, "New wt is not legitimate.");
            return Err(err);
        }
        // Do computation.
        let current_active_wt = self.active_wt.clone();
        self.retired_wts.insert(current_active_wt);
        self.not_active_legitimate_wts.remove(&new_active_wt);
        self.active_wt = new_active_wt;

        // Log finish.
        let result = ();
        function_finish_log!(result);
        Ok(result)
    }
}

#[derive(Debug, Display, Error)]
pub enum WtIdsCollectionError {
    NewWtIsNotInTheListOfNotActiveLegitimateWts,
}
