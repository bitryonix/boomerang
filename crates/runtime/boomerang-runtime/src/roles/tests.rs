use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddrV4,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use boomerang_config::{
    BoomerangNetworkConfig, ProcessBootstrap, ProcessConfig, ProcessRoutes,
    PublishedProcessIdentity, WithdrawalConfig, load_published_process_identity,
};
use protocol::constructs::{BitcoinCoreAuth, SarId, WtId, WtIdsCollection};

use super::{build_role_runtime, prelude::*};

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
        "boomerang-role-runtime-fixture-{prefix}-{}-{}.toml",
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

fn sample_state_dir(role: TransportRole) -> PathBuf {
    std::env::temp_dir().join(format!(
        "boomerang-role-runtime-{}-{}",
        role.as_str(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn sample_config(role: TransportRole) -> ProcessConfig {
    ProcessConfig {
        role,
        instance_id: format!("{}-1", role.as_str()),
        state_dir: sample_state_dir(role),
        bootstrap: match role {
            TransportRole::Wt => ProcessBootstrap::Wt {
                rpc_client_url: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 18443),
                rpc_client_auth: BitcoinCoreAuth::None,
            },
            TransportRole::Sar => ProcessBootstrap::Sar {},
            TransportRole::Peer => ProcessBootstrap::Peer {
                peer_index: 0,
                total_peers: 5,
                is_withdrawal_initiator: true,
                rpc_client_url: SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 18443),
                rpc_client_auth: BitcoinCoreAuth::None,
                wt_ids_collection: sample_wt_ids(),
                sar_ids_collection: BTreeSet::from([sample_sar_id()]),
            },
            TransportRole::Niso => ProcessBootstrap::Niso {},
            TransportRole::Iso => ProcessBootstrap::Iso {},
            TransportRole::Boomlet => ProcessBootstrap::Boomlet {
                slot: BoomletSlot::Primary,
            },
            TransportRole::Phone => ProcessBootstrap::Phone {
                sar_id: sample_sar_id(),
            },
            TransportRole::St => ProcessBootstrap::St {},
        },
        routes: match role {
            TransportRole::Wt => ProcessRoutes::Wt {
                peer_links: BTreeMap::new(),
                sar_links: BTreeMap::new(),
            },
            TransportRole::Sar => ProcessRoutes::Sar {
                peer_link: "sar-peer".to_owned(),
                wt_link: "sar-peer".to_owned(),
            },
            TransportRole::Peer => ProcessRoutes::Peer {
                wt_link: "peer-1".to_owned(),
                sar_link: "peer-1".to_owned(),
                phone_link: "peer-1".to_owned(),
                iso_link: "peer-1".to_owned(),
                niso_link: "peer-1".to_owned(),
                st_link: "peer-1".to_owned(),
                boomlet_link: "peer-1".to_owned(),
                boomletwo_link: "peer-1".to_owned(),
                peer_links: BTreeMap::new(),
            },
            TransportRole::Niso => ProcessRoutes::Niso {
                peer_link: "niso-peer".to_owned(),
            },
            TransportRole::Iso => ProcessRoutes::Iso {
                peer_link: "iso-peer".to_owned(),
            },
            TransportRole::Boomlet => ProcessRoutes::Boomlet {
                peer_link: "boomlet-peer".to_owned(),
            },
            TransportRole::Phone => ProcessRoutes::Phone {
                peer_link: "phone-peer".to_owned(),
            },
            TransportRole::St => ProcessRoutes::St {
                peer_link: "st-peer".to_owned(),
            },
        },
        links: Vec::new(),
        boomerang: BoomerangNetworkConfig::default(),
        withdrawal: WithdrawalConfig::default(),
    }
}

#[test]
fn build_role_runtime_creates_wt_runtime_with_public_identity() {
    let config = sample_config(TransportRole::Wt);
    let state_dir = config.state_dir.clone();

    let runtime =
        build_role_runtime(&config).expect("WT runtime should build without external ids");
    assert_eq!(runtime.role(), TransportRole::Wt);
    assert!(
        runtime
            .accepted_tags()
            .contains(&MessageTag::SetupNisoWtMessage1)
    );
    assert!(matches!(
        runtime.published_identity(),
        Some(PublishedProcessIdentity::Wt { .. })
    ));

    let _ = fs::remove_dir_all(state_dir);
}

#[test]
fn peer_runtime_accepts_peer_visible_outputs() {
    let runtime = build_role_runtime(&sample_config(TransportRole::Peer))
        .expect("peer runtime should build with public WT/SAR ids");
    assert!(
        runtime
            .accepted_tags()
            .contains(&MessageTag::SetupIsoOutput1)
    );
    assert!(
        runtime
            .accepted_tags()
            .contains(&MessageTag::WithdrawalStOutput1)
    );
}
