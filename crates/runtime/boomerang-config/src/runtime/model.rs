//! Data models for process and cluster manifests.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddrV4,
    path::PathBuf,
};

use boomerang_transport::LinkConfig;
use protocol::constructs::{BitcoinCoreAuth, SarId, WtId, WtIdsCollection};
use protocol_wire::control::TransportRole;
use serde::{Deserialize, Serialize};

use crate::poc::{BoomerangNetworkConfig, WithdrawalConfig};

/// Distinguishes the two boomlet processes attached to one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoomletSlot {
    Primary,
    Backup,
}

/// Role-specific bootstrap data needed to create one runtime entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessBootstrap {
    Wt {
        rpc_client_url: SocketAddrV4,
        rpc_client_auth: BitcoinCoreAuth,
    },
    Sar {},
    Peer {
        peer_index: usize,
        total_peers: usize,
        is_withdrawal_initiator: bool,
        rpc_client_url: SocketAddrV4,
        rpc_client_auth: BitcoinCoreAuth,
        wt_ids_collection: WtIdsCollection,
        sar_ids_collection: BTreeSet<SarId>,
    },
    Niso {},
    Iso {},
    Boomlet {
        slot: BoomletSlot,
    },
    Phone {
        sar_id: SarId,
    },
    St {},
}

impl ProcessBootstrap {
    /// Returns the role this bootstrap payload belongs to.
    pub fn role(&self) -> TransportRole {
        match self {
            Self::Wt { .. } => TransportRole::Wt,
            Self::Sar { .. } => TransportRole::Sar,
            Self::Peer { .. } => TransportRole::Peer,
            Self::Niso { .. } => TransportRole::Niso,
            Self::Iso { .. } => TransportRole::Iso,
            Self::Boomlet { .. } => TransportRole::Boomlet,
            Self::Phone { .. } => TransportRole::Phone,
            Self::St { .. } => TransportRole::St,
        }
    }
}

/// Role-specific route names used by the runtime to map transport links onto entity workflows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessRoutes {
    Wt {
        peer_links: BTreeMap<String, String>,
        sar_links: BTreeMap<String, String>,
    },
    Sar {
        peer_link: String,
        wt_link: String,
    },
    Peer {
        wt_link: String,
        sar_link: String,
        phone_link: String,
        iso_link: String,
        niso_link: String,
        st_link: String,
        boomlet_link: String,
        boomletwo_link: String,
        peer_links: BTreeMap<String, String>,
    },
    Niso {
        peer_link: String,
    },
    Iso {
        peer_link: String,
    },
    Boomlet {
        peer_link: String,
    },
    Phone {
        peer_link: String,
    },
    St {
        peer_link: String,
    },
}

impl ProcessRoutes {
    /// Returns the role this route payload belongs to.
    pub fn role(&self) -> TransportRole {
        match self {
            Self::Wt { .. } => TransportRole::Wt,
            Self::Sar { .. } => TransportRole::Sar,
            Self::Peer { .. } => TransportRole::Peer,
            Self::Niso { .. } => TransportRole::Niso,
            Self::Iso { .. } => TransportRole::Iso,
            Self::Boomlet { .. } => TransportRole::Boomlet,
            Self::Phone { .. } => TransportRole::Phone,
            Self::St { .. } => TransportRole::St,
        }
    }
}

/// Full runtime configuration for one Boomerang process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub role: TransportRole,
    pub instance_id: String,
    pub state_dir: PathBuf,
    pub bootstrap: ProcessBootstrap,
    pub routes: ProcessRoutes,
    pub links: Vec<LinkConfig>,
    pub boomerang: BoomerangNetworkConfig,
    pub withdrawal: WithdrawalConfig,
}

/// A supervisor manifest listing all processes in one cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterManifest {
    pub processes: Vec<ProcessConfig>,
}

/// Public identity material that WT or SAR publishes back to the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublishedProcessIdentity {
    Wt { wt_id: WtId },
    Sar { sar_id: SarId },
}

impl PublishedProcessIdentity {
    /// Returns the role this published identity belongs to.
    pub fn role(&self) -> TransportRole {
        match self {
            Self::Wt { .. } => TransportRole::Wt,
            Self::Sar { .. } => TransportRole::Sar,
        }
    }
}
