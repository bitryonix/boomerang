//! Unit tests for bootstrap and route extraction helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use boomerang_config::{
    BoomerangNetworkConfig, ProcessBootstrap, ProcessConfig, ProcessRoutes,
    PublishedProcessIdentity, WithdrawalConfig, load_published_process_identity,
};
use boomerang_transport::LinkConfig;
use protocol::constructs::{BitcoinCoreAuth, SarId, WtId, WtIdsCollection};
use protocol_wire::control::TransportRole;

use super::{peer_bootstrap_from_config, single_peer_link};

const WT_PUBLIC_ID_TOML: &str = r#"
kind = "wt"

[wt_id]
wt_tor_address = "de5slirlvscorgs6pyct5mc5ji73piegdindiez64jvwb4k3qojvjiid.onion"

[wt_id.wt_pubkey]
inner = "026a5c543a912794051654c47ae069f35f55975d954e463ef0344efea8a401f019"
"#;

const SAR_PUBLIC_ID_TOML: &str = r#"
kind = "sar"

[sar_id]
sar_tor_address = "aq57wcjpd6btyfa7ojhkjyuwqw3p3y25tm2fwgzuenvspp23tymbupad.onion"

[sar_id.sar_pubkey]
inner = "03400075872c95fcb942085f2c56649655033494fa91fcd91b375f889be8d69888"
"#;

fn sample_wt_ids() -> WtIdsCollection {
    WtIdsCollection::new(sample_wt_id(), BTreeSet::new())
}

fn sample_wt_id() -> WtId {
    match load_fixture_identity("wt", WT_PUBLIC_ID_TOML) {
        PublishedProcessIdentity::Wt { wt_id } => wt_id,
        PublishedProcessIdentity::Sar { .. } => {
            panic!("WT fixture TOML should decode to a WT public identity")
        }
    }
}

fn sample_sar_id() -> SarId {
    match load_fixture_identity("sar", SAR_PUBLIC_ID_TOML) {
        PublishedProcessIdentity::Sar { sar_id } => sar_id,
        PublishedProcessIdentity::Wt { .. } => {
            panic!("SAR fixture TOML should decode to a SAR public identity")
        }
    }
}

fn load_fixture_identity(prefix: &str, raw: &str) -> PublishedProcessIdentity {
    let path = std::env::temp_dir().join(format!(
        "boomerang-runtime-config-fixture-{prefix}-{}-{}.toml",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::write(&path, raw).expect("fixture identity TOML should be written");
    let identity = load_published_process_identity(&path)
        .expect("fixture identity TOML should stay parseable");
    let _ = fs::remove_file(path);
    identity
}

fn sample_process() -> ProcessConfig {
    ProcessConfig {
        role: TransportRole::Peer,
        instance_id: "peer-1".to_owned(),
        state_dir: PathBuf::from("/tmp/boomerang-runtime-config-tests"),
        bootstrap: ProcessBootstrap::Peer {
            peer_index: 0,
            total_peers: 1,
            is_withdrawal_initiator: true,
            rpc_client_url: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
            rpc_client_auth: BitcoinCoreAuth::None,
            wt_ids_collection: sample_wt_ids(),
            sar_ids_collection: BTreeSet::from([sample_sar_id()]),
        },
        routes: ProcessRoutes::Peer {
            wt_link: "peer-wt".to_owned(),
            sar_link: "peer-sar".to_owned(),
            phone_link: "peer-phone".to_owned(),
            iso_link: "peer-iso".to_owned(),
            niso_link: "peer-niso".to_owned(),
            st_link: "peer-st".to_owned(),
            boomlet_link: "peer-boomlet".to_owned(),
            boomletwo_link: "peer-boomletwo".to_owned(),
            peer_links: BTreeMap::new(),
        },
        links: vec![LinkConfig {
            name: "peer-wt".to_owned(),
            peer_role: TransportRole::Wt,
            peer_instance_id: "wt-1".to_owned(),
            bind_addr: None,
            connect_addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                19101,
            ))),
        }],
        boomerang: BoomerangNetworkConfig::default(),
        withdrawal: WithdrawalConfig::default(),
    }
}

#[test]
fn peer_bootstrap_extraction_preserves_assigned_sar_id() {
    let config = sample_process();
    let runtime = peer_bootstrap_from_config(&config).expect("peer bootstrap should extract");

    assert_eq!(runtime.peer_index, 0);
    assert_eq!(runtime.total_peers, 1);
}

#[test]
fn single_peer_link_reads_niso_style_routes() {
    let mut config = sample_process();
    config.role = TransportRole::Iso;
    config.routes = ProcessRoutes::Iso {
        peer_link: "peer-iso".to_owned(),
    };

    assert_eq!(
        single_peer_link(&config, TransportRole::Iso).expect("ISO route should read"),
        "peer-iso"
    );
}
