//! Published-identity helpers for the local POC topology.

use std::collections::BTreeMap;

use protocol::constructs::{SarId, WtId};

use super::{error::LocalPocError, ids::sar_instance_id};

/// Public WT/SAR identities that the local POC supervisor collected before peer bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPocPublishedIdentities {
    pub(super) wt_id: WtId,
    pub(super) sar_ids_by_instance: BTreeMap<String, SarId>,
}

impl LocalPocPublishedIdentities {
    /// Creates one published-identity set for the deterministic local POC topology.
    pub fn new(wt_id: WtId, sar_ids_by_instance: BTreeMap<String, SarId>) -> Self {
        Self {
            wt_id,
            sar_ids_by_instance,
        }
    }

    /// Returns the published WT id for the active watchtower.
    pub fn wt_id(&self) -> &WtId {
        &self.wt_id
    }

    /// Returns the published SAR id for one peer-numbered SAR instance.
    pub(super) fn sar_id_for_peer(&self, peer_number: usize) -> Result<&SarId, LocalPocError> {
        let instance_id = sar_instance_id(peer_number);
        self.sar_ids_by_instance
            .get(&instance_id)
            .ok_or(LocalPocError::MissingProcessDraft { instance_id })
    }

    /// Returns the number of published SAR ids currently tracked.
    pub fn sar_count(&self) -> usize {
        self.sar_ids_by_instance.len()
    }
}
