//! Tests for runtime manifest models and TOML helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use boomerang_transport::LinkConfig;
use protocol::constructs::{BitcoinCoreAuth, SarId, WtId, WtIdsCollection};
use protocol_wire::control::TransportRole;

use crate::{
    BoomerangNetworkConfig, RuntimeConfigError, WithdrawalConfig,
    poc::defaults::workspace_root,
    runtime::{
        io::{
            load_cluster_manifest, load_process_config, load_published_process_identity,
            published_identity_path, save_published_process_identity,
        },
        model::{
            BoomletSlot, ClusterManifest, ProcessBootstrap, ProcessConfig, ProcessRoutes,
            PublishedProcessIdentity,
        },
    },
};

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

fn sample_wt_ids() -> WtIdsCollection {
    WtIdsCollection::new(sample_wt_id(), BTreeSet::new())
}

fn sample_sar_id() -> SarId {
    match toml::from_str::<PublishedProcessIdentity>(SAR_PUBLIC_ID_TOML)
        .expect("SAR fixture TOML should stay parseable")
    {
        PublishedProcessIdentity::Sar { sar_id } => sar_id,
        PublishedProcessIdentity::Wt { .. } => {
            panic!("SAR fixture TOML should decode to a SAR public identity")
        }
    }
}

fn sample_bootstrap(role: TransportRole) -> ProcessBootstrap {
    match role {
        TransportRole::Wt => ProcessBootstrap::Wt {
            rpc_client_url: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
            rpc_client_auth: BitcoinCoreAuth::None,
        },
        TransportRole::Sar => ProcessBootstrap::Sar {},
        TransportRole::Peer => ProcessBootstrap::Peer {
            peer_index: 0,
            total_peers: 1,
            is_withdrawal_initiator: true,
            rpc_client_url: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
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
    }
}

fn sample_routes(role: TransportRole, link_name: &str) -> ProcessRoutes {
    match role {
        TransportRole::Wt => ProcessRoutes::Wt {
            peer_links: BTreeMap::from([("peer-1".to_owned(), link_name.to_owned())]),
            sar_links: BTreeMap::new(),
        },
        TransportRole::Sar => ProcessRoutes::Sar {
            peer_link: link_name.to_owned(),
            wt_link: link_name.to_owned(),
        },
        TransportRole::Peer => ProcessRoutes::Peer {
            wt_link: link_name.to_owned(),
            sar_link: link_name.to_owned(),
            phone_link: link_name.to_owned(),
            iso_link: link_name.to_owned(),
            niso_link: link_name.to_owned(),
            st_link: link_name.to_owned(),
            boomlet_link: link_name.to_owned(),
            boomletwo_link: link_name.to_owned(),
            peer_links: BTreeMap::new(),
        },
        TransportRole::Niso => ProcessRoutes::Niso {
            peer_link: link_name.to_owned(),
        },
        TransportRole::Iso => ProcessRoutes::Iso {
            peer_link: link_name.to_owned(),
        },
        TransportRole::Boomlet => ProcessRoutes::Boomlet {
            peer_link: link_name.to_owned(),
        },
        TransportRole::Phone => ProcessRoutes::Phone {
            peer_link: link_name.to_owned(),
        },
        TransportRole::St => ProcessRoutes::St {
            peer_link: link_name.to_owned(),
        },
    }
}

fn sample_process(role: TransportRole, instance_id: &str) -> ProcessConfig {
    ProcessConfig {
        role,
        instance_id: instance_id.to_owned(),
        state_dir: PathBuf::from("/tmp/boomerang-test"),
        bootstrap: sample_bootstrap(role),
        routes: sample_routes(role, "peer-wt"),
        links: vec![LinkConfig {
            name: "peer-wt".to_owned(),
            peer_role: TransportRole::Wt,
            peer_instance_id: "wt-1".to_owned(),
            bind_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9000))),
            connect_addr: None,
        }],
        boomerang: BoomerangNetworkConfig::default(),
        withdrawal: WithdrawalConfig::default(),
    }
}

#[test]
fn process_config_rejects_duplicate_link_names() {
    let mut config = sample_process(TransportRole::Peer, "peer-1");
    config.links.push(config.links[0].clone());

    let err = config.validate().unwrap_err();
    assert!(matches!(err, RuntimeConfigError::DuplicateLinkName(_)));
}

#[test]
fn cluster_manifest_requires_known_peers() {
    let manifest = ClusterManifest {
        processes: vec![sample_process(TransportRole::Peer, "peer-1")],
    };

    let err = manifest.validate().unwrap_err();
    assert!(matches!(err, RuntimeConfigError::MissingPeerProcess { .. }));
}

#[test]
fn process_config_rejects_route_links_that_do_not_exist() {
    let mut config = sample_process(TransportRole::Peer, "peer-1");
    config.routes = ProcessRoutes::Peer {
        wt_link: "missing".to_owned(),
        sar_link: "peer-wt".to_owned(),
        phone_link: "peer-wt".to_owned(),
        iso_link: "peer-wt".to_owned(),
        niso_link: "peer-wt".to_owned(),
        st_link: "peer-wt".to_owned(),
        boomlet_link: "peer-wt".to_owned(),
        boomletwo_link: "peer-wt".to_owned(),
        peer_links: BTreeMap::new(),
    };

    let err = config.validate().unwrap_err();
    assert!(matches!(err, RuntimeConfigError::MissingRouteLink { .. }));
}

#[test]
fn checked_in_minimal_process_example_loads_and_validates() {
    let path = workspace_root().join("crates/runtime/boomerang-node/examples/minimal-process.toml");
    let process = load_process_config(&path).unwrap_or_else(|error| {
        panic!("expected {} to parse and validate: {error}", path.display())
    });

    assert_eq!(process.role, TransportRole::St);
    assert_eq!(process.instance_id, "st-1");
}

#[test]
fn checked_in_minimal_cluster_example_loads_and_validates() {
    let path = workspace_root().join("crates/runtime/boomerang-node/examples/minimal-cluster.toml");
    let manifest = load_cluster_manifest(&path).unwrap_or_else(|error| {
        panic!("expected {} to parse and validate: {error}", path.display())
    });

    assert_eq!(manifest.processes.len(), 2);
    assert!(
        manifest
            .processes
            .iter()
            .any(|process| process.role == TransportRole::St)
    );
    assert!(
        manifest
            .processes
            .iter()
            .any(|process| process.role == TransportRole::Iso)
    );
}

#[test]
fn load_process_config_rejects_removed_wt_bootstrap_identity_fields() {
    let temp_dir = std::env::temp_dir().join(format!(
        "boomerang-config-legacy-secret-process-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap_or_else(|error| {
        panic!("expected temporary directory creation to succeed: {error}")
    });
    let path = temp_dir.join("wt.toml");
    fs::write(
        &path,
        r#"
role = "wt"
instance_id = "wt-1"
state_dir = "/tmp/wt"

[bootstrap]
kind = "wt"
private_key = "legacy-secret"
tor_secret_key = "legacy-tor-secret"
wt_id = { wt_tor_address = "still-public-but-removed.onion" }
"#,
    )
    .unwrap_or_else(|error| panic!("expected legacy test config to be written: {error}"));

    let error = load_process_config(&path).unwrap_err();
    assert!(matches!(
        error,
        RuntimeConfigError::RemovedWtSarBootstrapFields { .. }
    ));
    assert!(error.to_string().contains("create identity internally"));

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn load_cluster_manifest_rejects_removed_sar_bootstrap_identity_fields() {
    let temp_dir = std::env::temp_dir().join(format!(
        "boomerang-config-legacy-secret-cluster-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap_or_else(|error| {
        panic!("expected temporary directory creation to succeed: {error}")
    });
    let path = temp_dir.join("cluster.toml");
    fs::write(
        &path,
        r#"
[[processes]]
role = "sar"
instance_id = "sar-1"
state_dir = "/tmp/sar"

[processes.bootstrap]
kind = "sar"
private_key = "legacy-secret"
tor_secret_key = "legacy-tor-secret"
sar_id = { sar_tor_address = "still-public-but-removed.onion" }
"#,
    )
    .unwrap_or_else(|error| panic!("expected legacy test cluster config to be written: {error}"));

    let error = load_cluster_manifest(&path).unwrap_err();
    assert!(matches!(
        error,
        RuntimeConfigError::RemovedWtSarBootstrapFields { .. }
    ));
    assert!(error.to_string().contains("sar:sar-1"));

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn published_identity_artifacts_round_trip_through_toml_helpers() {
    let temp_dir = std::env::temp_dir().join(format!(
        "boomerang-config-runtime-tests-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap_or_else(|error| {
        panic!("expected temporary directory creation to succeed: {error}")
    });
    let public_path = published_identity_path(&temp_dir);
    let public_identity = PublishedProcessIdentity::Sar {
        sar_id: sample_sar_id(),
    };

    save_published_process_identity(&public_path, &public_identity)
        .unwrap_or_else(|error| panic!("expected published identity helper to save TOML: {error}"));

    let loaded_public = load_published_process_identity(&public_path)
        .unwrap_or_else(|error| panic!("expected published identity helper to load TOML: {error}"));

    assert_eq!(loaded_public, public_identity);

    let _ = fs::remove_dir_all(temp_dir);
}
