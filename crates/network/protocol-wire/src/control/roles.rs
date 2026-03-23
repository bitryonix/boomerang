//! Transport roles used in process manifests and handshakes.

use serde::{Deserialize, Serialize};

/// Identifies the process role speaking over one transport link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportRole {
    Wt,
    Sar,
    Peer,
    Niso,
    Iso,
    Boomlet,
    Phone,
    St,
}

impl TransportRole {
    /// Returns the stable snake_case role name used in config files and progress logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wt => "wt",
            Self::Sar => "sar",
            Self::Peer => "peer",
            Self::Niso => "niso",
            Self::Iso => "iso",
            Self::Boomlet => "boomlet",
            Self::Phone => "phone",
            Self::St => "st",
        }
    }
}
