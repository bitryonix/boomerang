//! Tests for the deterministic local POC manifest builder.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use boomerang_config::{
    ClusterManifest, NetworkedPocConfig, PublishedProcessIdentity, load_cluster_manifest,
    load_published_process_identity, save_cluster_manifest,
};

use super::{
    builder::{
        default_node_bin, default_state_root, local_poc_cluster_manifest,
        local_poc_identity_processes,
    },
    identity::LocalPocPublishedIdentities,
    ids::{local_instance_id, peer_instance_id},
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

const EXTRA_PUBLIC_KEYS: [&str; 2] = [
    "026a5c543a912794051654c47ae069f35f55975d954e463ef0344efea8a401f019",
    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
];
const EXTRA_TOR_ADDRESSES: [&str; 2] = [
    "de5slirlvscorgs6pyct5mc5ji73piegdindiez64jvwb4k3qojvjiid.onion",
    "5jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwfmxqd.onion",
];

fn load_fixture_identity(prefix: &str, raw: &str) -> PublishedProcessIdentity {
    let path = std::env::temp_dir().join(format!(
        "boomerang-scenarios-fixture-{prefix}-{}-{}.toml",
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

fn published_identities() -> LocalPocPublishedIdentities {
    let wt_id = match load_fixture_identity("wt", WT_PUBLIC_ID_TOML) {
        PublishedProcessIdentity::Wt { wt_id } => wt_id,
        PublishedProcessIdentity::Sar { .. } => {
            panic!("WT fixture TOML should decode to a WT public identity")
        }
    };
    let sar_id_template = match load_fixture_identity("sar", SAR_PUBLIC_ID_TOML) {
        PublishedProcessIdentity::Sar { sar_id } => sar_id,
        PublishedProcessIdentity::Wt { .. } => {
            panic!("SAR fixture TOML should decode to a SAR public identity")
        }
    };
    let sar_ids_by_instance = (1..=5)
        .map(|peer_number| {
            let sar_id = if peer_number == 1 {
                sar_id_template.clone()
            } else {
                let pubkey = EXTRA_PUBLIC_KEYS[(peer_number - 2) % EXTRA_PUBLIC_KEYS.len()];
                let tor_address = EXTRA_TOR_ADDRESSES[(peer_number - 2) % EXTRA_TOR_ADDRESSES.len()];
                let raw = format!(
                    "kind = \"sar\"\n\n[sar_id]\nsar_tor_address = \"{tor_address}\"\n\n[sar_id.sar_pubkey]\ninner = \"{pubkey}\"\n"
                );
                match load_fixture_identity(&format!("sar-{peer_number}"), &raw) {
                    PublishedProcessIdentity::Sar { sar_id } => sar_id,
                    PublishedProcessIdentity::Wt { .. } => {
                        panic!("generated SAR fixture TOML should decode to a SAR public identity")
                    }
                }
            };
            (format!("sar-{peer_number}"), sar_id)
        })
        .collect::<BTreeMap<_, _>>();

    LocalPocPublishedIdentities::new(wt_id, sar_ids_by_instance)
}

fn test_manifest() -> ClusterManifest {
    local_poc_cluster_manifest(
        &NetworkedPocConfig::default(),
        &published_identities(),
        &std::env::temp_dir().join("boomerang-poc-tests"),
        25000,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
        protocol::constructs::BitcoinCoreAuth::None,
    )
    .expect("local POC manifest should build")
}

#[test]
fn generated_manifest_contains_all_41_processes() {
    assert_eq!(test_manifest().processes.len(), 41);
}

#[test]
fn default_node_bin_points_at_the_workspace_managed_binary() {
    let node_bin = default_node_bin();
    if let Some(env_path) = std::env::var_os("CARGO_BIN_EXE_boomerang-node") {
        assert_eq!(node_bin, PathBuf::from(env_path));
        return;
    }

    assert_eq!(
        node_bin,
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|candidate| candidate.join(".git").exists())
            .expect("workspace root should be discoverable from the scenarios crate")
            .join("target")
            .join("debug")
            .join("boomerang-node")
    );
}

#[test]
fn default_state_root_lives_under_the_workspace_root() {
    let state_root = default_state_root();

    assert!(state_root.ends_with("poc-runs"));
    assert!(
        state_root.starts_with(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .find(|candidate| candidate.join(".git").exists())
                .expect("workspace root should be discoverable from the scenarios crate")
        ),
        "default state root should stay visible under the repository root"
    );
}

#[test]
fn identity_processes_cover_one_wt_and_all_sars_without_public_ids_in_bootstrap() {
    let processes = local_poc_identity_processes(
        &NetworkedPocConfig::default(),
        &std::env::temp_dir().join("boomerang-poc-identity-tests"),
        25000,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
        protocol::constructs::BitcoinCoreAuth::None,
    )
    .expect("identity-stage process configs should build");

    assert_eq!(processes.len(), 6);
    assert_eq!(
        processes
            .iter()
            .filter(|process| process.role == protocol_wire::control::TransportRole::Wt)
            .count(),
        1
    );
    assert_eq!(
        processes
            .iter()
            .filter(|process| process.role == protocol_wire::control::TransportRole::Sar)
            .count(),
        5
    );
    assert!(processes.iter().all(|process| {
        matches!(
            &process.bootstrap,
            boomerang_config::ProcessBootstrap::Wt { .. }
                | boomerang_config::ProcessBootstrap::Sar {}
        )
    }));
}

#[test]
fn generated_manifest_uses_unique_process_ids() {
    let manifest = test_manifest();
    let unique_ids = manifest
        .processes
        .iter()
        .map(|process| process.instance_id.clone())
        .collect::<BTreeSet<_>>();

    assert_eq!(unique_ids.len(), manifest.processes.len());
}

#[test]
fn generated_manifest_assigns_unique_ports_and_paired_links() {
    let manifest = test_manifest();
    let mut bind_ports = BTreeSet::new();
    let mut link_counts = BTreeMap::<String, usize>::new();

    for process in &manifest.processes {
        for link in &process.links {
            *link_counts.entry(link.name.clone()).or_default() += 1;
            if let Some(addr) = link.bind_addr {
                bind_ports.insert(addr);
            }
        }
    }

    assert_eq!(bind_ports.len(), 55);
    assert!(link_counts.values().all(|count| *count == 2));
}

#[test]
fn sar_peer_links_bind_on_sar_side_for_prelaunch_compatibility() {
    let manifest = test_manifest();
    let sar = manifest
        .processes
        .iter()
        .find(|process| process.instance_id == "sar-1")
        .expect("manifest should contain sar-1");
    let peer = manifest
        .processes
        .iter()
        .find(|process| process.instance_id == "peer-1")
        .expect("manifest should contain peer-1");

    let sar_link = sar
        .links
        .iter()
        .find(|link| link.name == "peer-1--sar-1")
        .expect("sar-1 should keep the peer link");
    let peer_link = peer
        .links
        .iter()
        .find(|link| link.name == "peer-1--sar-1")
        .expect("peer-1 should keep the SAR link");

    assert!(sar_link.bind_addr.is_some());
    assert!(sar_link.connect_addr.is_none());
    assert!(peer_link.bind_addr.is_none());
    assert!(peer_link.connect_addr.is_some());
}

#[test]
fn generated_manifest_gives_each_peer_all_local_entities() {
    let manifest = test_manifest();
    let instances = manifest
        .processes
        .iter()
        .map(|process| process.instance_id.as_str())
        .collect::<BTreeSet<_>>();

    for peer_number in 1..=5 {
        for suffix in ["peer", "niso", "iso", "phone", "boomlet", "boomletwo", "st"] {
            let instance_id = if suffix == "peer" {
                peer_instance_id(peer_number)
            } else {
                local_instance_id(peer_number, suffix)
            };
            assert!(instances.contains(instance_id.as_str()));
        }
    }
}

#[test]
fn generated_manifest_round_trips_through_config_io() {
    let manifest = test_manifest();
    let path = std::env::temp_dir().join(format!(
        "boomerang-local-poc-roundtrip-{}.toml",
        std::process::id()
    ));
    save_cluster_manifest(&path, &manifest).expect("manifest should save");
    let loaded = load_cluster_manifest(&path).expect("manifest should load");

    assert_eq!(loaded.processes.len(), manifest.processes.len());
}
