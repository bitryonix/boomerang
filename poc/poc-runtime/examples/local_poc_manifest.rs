//! Prints a compact summary of the deterministic local POC manifest.

use std::{
    collections::BTreeMap,
    fs,
    net::{Ipv4Addr, SocketAddrV4},
    time::{SystemTime, UNIX_EPOCH},
};

use boomerang_config::{
    NetworkedPocConfig, PublishedProcessIdentity, load_published_process_identity,
};
use poc_runtime::{LocalPocPublishedIdentities, default_state_root, local_poc_cluster_manifest};
use protocol::constructs::{BitcoinCoreAuth, SarId, WtId};

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
        "boomerang-poc-example-fixture-{prefix}-{}-{}.toml",
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

fn sample_sar_id_for_peer(peer_number: usize) -> SarId {
    if peer_number == 1 {
        return sample_sar_id();
    }

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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identities = LocalPocPublishedIdentities::new(
        sample_wt_id(),
        (1..=5)
            .map(|peer_number| {
                (
                    format!("sar-{peer_number}"),
                    sample_sar_id_for_peer(peer_number),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    );
    let manifest = local_poc_cluster_manifest(
        &NetworkedPocConfig::default(),
        &identities,
        &default_state_root(),
        26000,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18443),
        BitcoinCoreAuth::None,
    )?;

    println!(
        "generated {} processes and {} total links",
        manifest.processes.len(),
        manifest
            .processes
            .iter()
            .map(|process| process.links.len())
            .sum::<usize>()
    );
    Ok(())
}
