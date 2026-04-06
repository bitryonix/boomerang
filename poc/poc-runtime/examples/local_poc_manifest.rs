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

/// Minimal WT identity fixture used to keep the example deterministic.
const WT_PUBLIC_ID_TOML: &str = r#"
kind = "wt"

[wt_id]
wt_tor_address = "de5slirlvscorgs6pyct5mc5ji73piegdindiez64jvwb4k3qojvjiid.onion"

[wt_id.wt_pubkey]
inner = "026a5c543a912794051654c47ae069f35f55975d954e463ef0344efea8a401f019"
"#;

/// Minimal SAR identity fixture used to seed the example manifest.
const SAR_PUBLIC_ID_TOML: &str = r#"
kind = "sar"

[sar_id]
sar_tor_address = "aq57wcjpd6btyfa7ojhkjyuwqw3p3y25tm2fwgzuenvspp23tymbupad.onion"

[sar_id.sar_pubkey]
inner = "03400075872c95fcb942085f2c56649655033494fa91fcd91b375f889be8d69888"
"#;

/// Extra compressed public keys used to synthesize additional SAR identities.
const EXTRA_PUBLIC_KEYS: [&str; 2] = [
    "026a5c543a912794051654c47ae069f35f55975d954e463ef0344efea8a401f019",
    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
];
/// Extra onion addresses paired with the synthetic SAR identities above.
const EXTRA_TOR_ADDRESSES: [&str; 2] = [
    "de5slirlvscorgs6pyct5mc5ji73piegdindiez64jvwb4k3qojvjiid.onion",
    "5jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwfmxqd.onion",
];

/// Persists one inline fixture to a temporary TOML file and parses it through the real loader.
///
/// # Errors
/// Returns any filesystem or deserialization error produced while materializing the fixture.
fn load_fixture_identity(
    prefix: &str,
    raw: &str,
) -> Result<PublishedProcessIdentity, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "boomerang-poc-example-fixture-{prefix}-{}-{}.toml",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::write(&path, raw)?;
    let identity = load_published_process_identity(&path)?;
    let _ = fs::remove_file(path);
    Ok(identity)
}

/// Loads the deterministic WT identity fixture for the example cluster.
///
/// # Errors
/// Returns an error when the inline fixture cannot be parsed as a WT identity.
fn sample_wt_id() -> Result<WtId, Box<dyn std::error::Error>> {
    match load_fixture_identity("wt", WT_PUBLIC_ID_TOML)? {
        PublishedProcessIdentity::Wt { wt_id } => Ok(wt_id),
        PublishedProcessIdentity::Sar { .. } => Err(std::io::Error::other(
            "WT fixture TOML should decode to a WT public identity",
        )
        .into()),
    }
}

/// Loads the baseline SAR identity fixture for the example cluster.
///
/// # Errors
/// Returns an error when the inline fixture cannot be parsed as a SAR identity.
fn sample_sar_id() -> Result<SarId, Box<dyn std::error::Error>> {
    match load_fixture_identity("sar", SAR_PUBLIC_ID_TOML)? {
        PublishedProcessIdentity::Sar { sar_id } => Ok(sar_id),
        PublishedProcessIdentity::Wt { .. } => Err(std::io::Error::other(
            "SAR fixture TOML should decode to a SAR public identity",
        )
        .into()),
    }
}

/// Creates a deterministic SAR identity for the requested peer slot.
///
/// Peer `1` reuses the baseline SAR fixture, while later peers cycle through extra public-key
/// and onion-address fixtures so the manifest can materialize several distinct SAR processes.
///
/// # Errors
/// Returns an error when the generated fixture cannot be parsed as a SAR identity.
fn sample_sar_id_for_peer(peer_number: usize) -> Result<SarId, Box<dyn std::error::Error>> {
    if peer_number == 1 {
        return sample_sar_id();
    }

    let pubkey = EXTRA_PUBLIC_KEYS[(peer_number - 2) % EXTRA_PUBLIC_KEYS.len()];
    let tor_address = EXTRA_TOR_ADDRESSES[(peer_number - 2) % EXTRA_TOR_ADDRESSES.len()];
    let raw = format!(
        "kind = \"sar\"\n\n[sar_id]\nsar_tor_address = \"{tor_address}\"\n\n[sar_id.sar_pubkey]\ninner = \"{pubkey}\"\n"
    );

    match load_fixture_identity(&format!("sar-{peer_number}"), &raw)? {
        PublishedProcessIdentity::Sar { sar_id } => Ok(sar_id),
        PublishedProcessIdentity::Wt { .. } => Err(std::io::Error::other(
            "generated SAR fixture TOML should decode to a SAR public identity",
        )
        .into()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identities = LocalPocPublishedIdentities::new(
        sample_wt_id()?,
        (1..=5)
            .map(|peer_number| {
                Ok::<_, Box<dyn std::error::Error>>((
                    format!("sar-{peer_number}"),
                    sample_sar_id_for_peer(peer_number)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?,
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
