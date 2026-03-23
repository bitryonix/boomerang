//! State query and snapshot payloads used by runtime helpers.

use protocol::constructs::{BoomerangParams, PeerId, WtPeerId};
use serde::{Deserialize, Serialize};

/// Queries the current NISO state snapshot from a runtime process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct QueryNisoState;

/// Snapshot of the NISO state relevant to peer bootstrap and debug inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NisoStateSnapshot {
    peer_id: Option<PeerId>,
    wt_peer_id: Option<WtPeerId>,
    boomerang_params: Option<BoomerangParams>,
}

impl NisoStateSnapshot {
    /// Creates a snapshot payload with the currently known NISO state.
    pub fn new(
        peer_id: Option<PeerId>,
        wt_peer_id: Option<WtPeerId>,
        boomerang_params: Option<BoomerangParams>,
    ) -> Self {
        Self {
            peer_id,
            wt_peer_id,
            boomerang_params,
        }
    }

    /// Decomposes the snapshot into owned state parts.
    pub fn into_parts(self) -> (Option<PeerId>, Option<WtPeerId>, Option<BoomerangParams>) {
        (self.peer_id, self.wt_peer_id, self.boomerang_params)
    }
}
