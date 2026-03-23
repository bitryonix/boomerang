//! Story-first example showing how to build and validate a small manifest in memory.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
};

use boomerang_config::{
    BoomerangNetworkConfig, BoomletSlot, ClusterManifest, ProcessBootstrap, ProcessConfig,
    ProcessRoutes, PublishedProcessIdentity, WithdrawalConfig,
};
use boomerang_transport::LinkConfig;
use protocol::constructs::{BitcoinCoreAuth, WtId};
use protocol_wire::control::TransportRole;

const WT_PUBLIC_ID_TOML: &str = r#"
kind = "wt"

[wt_id]
wt_tor_address = "de5slirlvscorgs6pyct5mc5ji73piegdindiez64jvwb4k3qojvjiid.onion"

[wt_id.wt_pubkey]
inner = "026a5c543a912794051654c47ae069f35f55975d954e463ef0344efea8a401f019"
"#;

fn sample_wt_id() -> WtId {
    match toml::from_str::<PublishedProcessIdentity>(WT_PUBLIC_ID_TOML)
        .expect("WT fixture TOML should stay parseable")
    {
        PublishedProcessIdentity::Wt { wt_id } => wt_id,
        PublishedProcessIdentity::Sar { .. } => {
            panic!("WT fixture TOML should decode to a WT public identity")
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Imagine an operator tool preparing a tiny two-process smoke-test cluster before handing the
    // manifest to `boomerang-node cluster up`.
    let boomerang = BoomerangNetworkConfig::default();
    let withdrawal = WithdrawalConfig::default();
    let wt_id = sample_wt_id();

    let wt = ProcessConfig {
        role: TransportRole::Wt,
        instance_id: "wt-1".to_owned(),
        state_dir: PathBuf::from("/tmp/boomerang-node/wt-1"),
        bootstrap: ProcessBootstrap::Wt {
            rpc_client_url: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
            rpc_client_auth: BitcoinCoreAuth::None,
        },
        routes: ProcessRoutes::Wt {
            peer_links: BTreeMap::from([("peer-1".to_owned(), "wt-peer-1".to_owned())]),
            sar_links: BTreeMap::new(),
        },
        links: vec![LinkConfig {
            name: "wt-peer-1".to_owned(),
            peer_role: TransportRole::Peer,
            peer_instance_id: "peer-1".to_owned(),
            bind_addr: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                19101,
            ))),
            connect_addr: None,
        }],
        boomerang: boomerang.clone(),
        withdrawal: withdrawal.clone(),
    };

    let peer = ProcessConfig {
        role: TransportRole::Peer,
        instance_id: "peer-1".to_owned(),
        state_dir: PathBuf::from("/tmp/boomerang-node/peer-1"),
        bootstrap: ProcessBootstrap::Peer {
            peer_index: 0,
            total_peers: 1,
            is_withdrawal_initiator: true,
            rpc_client_url: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
            rpc_client_auth: BitcoinCoreAuth::None,
            wt_ids_collection: protocol::constructs::WtIdsCollection::new(wt_id, BTreeSet::new()),
            sar_ids_collection: BTreeSet::new(),
        },
        routes: ProcessRoutes::Peer {
            wt_link: "wt-peer-1".to_owned(),
            sar_link: "wt-peer-1".to_owned(),
            phone_link: "wt-peer-1".to_owned(),
            iso_link: "wt-peer-1".to_owned(),
            niso_link: "wt-peer-1".to_owned(),
            st_link: "wt-peer-1".to_owned(),
            boomlet_link: "wt-peer-1".to_owned(),
            boomletwo_link: "wt-peer-1".to_owned(),
            peer_links: BTreeMap::new(),
        },
        links: vec![LinkConfig {
            name: "wt-peer-1".to_owned(),
            peer_role: TransportRole::Wt,
            peer_instance_id: "wt-1".to_owned(),
            bind_addr: None,
            connect_addr: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                19101,
            ))),
        }],
        boomerang,
        withdrawal,
    };

    let manifest = ClusterManifest {
        processes: vec![wt, peer],
    };

    manifest.validate()?;
    println!("validated {} process configs", manifest.processes.len());
    let _ = BoomletSlot::Primary;
    Ok(())
}
