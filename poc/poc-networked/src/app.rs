//! Application orchestration for the legacy `poc-networked` binary.
//!
//! # Why this exists
//! The legacy channel-based runner still has substantial startup and wiring logic, but that logic
//! does not belong in `main.rs`. This module keeps the bootstrap small while preserving the old
//! behavior for regression comparisons.
//!
//! # Role in the system
//! [`run`] is the single entrypoint used by [`crate::main`] after tracing is installed.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

use boomerang_config::{BoomerangNetworkConfig, ConfigError, NetworkedPocConfig};
use boomlet::Boomlet;
use corepc_node::{Conf, Node, P2P};
use iso::Iso;
use niso::{Niso, NisoCreateParams};
use peer::Peer;
use phone::Phone;
use protocol::constructs::{BitcoinCoreAuth, SarId, WtIdsCollection};
use sar::Sar;
use st::St;
use tokio::{sync::Barrier, task::JoinSet};
use tracing::info;
use wt::{Wt, WtCreateParams};

use crate::{
    actors::{
        peer_actor::{InitiatorRuntime, PeerActor, PeerEntities, PeerPorts},
        sar_actor::SarActor,
        wt_actor::WtActor,
    },
    transport::{self, channel},
};

/// Runs the legacy channel-based proof-of-concept runtime.
///
/// # Why this exists
/// The historical Tokio-channel topology is still useful as a regression oracle while the newer
/// multi-process runtime grows. Keeping it runnable helps us compare behavior instead of relying
/// on memory or stale documentation.
///
/// # Role in the system
/// Called by [`crate::main`] after tracing bootstrap.
///
/// # Errors
/// Returns an error when the baked-in config is invalid, when the legacy topology assumptions are
/// violated, when entity startup fails, or when one of the actor tasks panics.
///
/// # Examples
/// The normal operator story is running the legacy concurrent prototype locally:
///
/// ```text
/// cargo run -p poc-networked
/// ```
pub(crate) async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    validate_topology(&config)?;

    let num_peers = config.topology.num_peers;
    let num_sars = config.topology.num_sars;
    let channel_capacity = config.topology.channel_capacity;

    info!(
        "NetworkedPoC: booting {num_peers} peers, {num_sars} SARs, and 1 WT with Tokio-channel transport (capacity {channel_capacity})."
    );

    let bitcoin_node = build_bitcoin_node(&config.boomerang)?;
    let rpc_client_url = bitcoin_node.params.rpc_socket;
    let rpc_client_auth = BitcoinCoreAuth::CookieFile(bitcoin_node.params.cookie_file.clone());

    let (sars, sar_ids) = build_sars(num_sars)?;
    let wt = build_wt(&config.boomerang, &rpc_client_auth, rpc_client_url)?;
    let wt_id = wt
        .get_wt_id()
        .ok_or_else(|| io::Error::other("WT initialization did not expose a WT id"))?;
    let wt_ids_collection = WtIdsCollection::new(wt_id, BTreeSet::new());

    let peer_directory = transport::PeerDirectory::new();
    let peer_registration_barrier = std::sync::Arc::new(Barrier::new(num_peers));
    let setup_barrier = std::sync::Arc::new(Barrier::new(num_peers + num_sars + 1));

    let peer_entities = sar_ids
        .iter()
        .take(num_peers)
        .map(|sar_id| {
            build_peer_entities(
                &config.boomerang,
                &rpc_client_auth,
                rpc_client_url,
                wt_ids_collection.clone(),
                sar_id.clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut peer_ports = Vec::with_capacity(num_peers);
    let mut peer_to_wt_rxs = Vec::with_capacity(num_peers);
    let mut wt_to_peer_txs = Vec::with_capacity(num_peers);
    let mut sar_ports = Vec::with_capacity(num_sars);
    let mut wt_to_sar_txs = Vec::with_capacity(num_sars);
    let mut sar_to_wt_rxs = Vec::with_capacity(num_sars);
    for _ in 0..num_peers {
        let (peer_to_wt_tx, peer_to_wt_rx) = channel(channel_capacity);
        let (wt_to_peer_tx, wt_to_peer_rx) = channel(channel_capacity);
        let (peer_to_sar_tx, peer_to_sar_rx) = channel(channel_capacity);
        let (sar_to_peer_tx, sar_to_peer_rx) = channel(channel_capacity);
        let (wt_to_sar_tx, wt_to_sar_rx) = channel(channel_capacity);
        let (sar_to_wt_tx, sar_to_wt_rx) = channel(channel_capacity);
        let (peer_to_peer_tx, peer_to_peer_rx) = channel(channel_capacity);

        peer_to_wt_rxs.push(peer_to_wt_rx);
        wt_to_peer_txs.push(wt_to_peer_tx);
        wt_to_sar_txs.push(wt_to_sar_tx);
        sar_to_wt_rxs.push(sar_to_wt_rx);
        sar_ports.push((peer_to_sar_rx, sar_to_peer_tx, wt_to_sar_rx, sar_to_wt_tx));
        peer_ports.push(PeerPorts {
            peer_to_wt_tx,
            wt_to_peer_rx,
            peer_to_sar_tx,
            sar_to_peer_rx,
            peer_to_peer_tx,
            peer_to_peer_rx,
        });
    }

    let sar_id_to_channel = sar_ids
        .iter()
        .enumerate()
        .map(|(index, sar_id)| (sar_id.clone(), index))
        .collect::<BTreeMap<_, _>>();

    let wt_actor = WtActor::new(
        wt,
        peer_to_wt_rxs,
        wt_to_peer_txs,
        sar_to_wt_rxs,
        wt_to_sar_txs,
        sar_id_to_channel,
        setup_barrier.clone(),
    );

    let sar_actors = sars
        .into_iter()
        .zip(sar_ports)
        .map(
            |(sar, (peer_to_sar_rx, sar_to_peer_tx, wt_to_sar_rx, sar_to_wt_tx))| {
                SarActor::new(
                    sar,
                    peer_to_sar_rx,
                    sar_to_peer_tx,
                    wt_to_sar_rx,
                    sar_to_wt_tx,
                    setup_barrier.clone(),
                )
            },
        )
        .collect::<Vec<_>>();

    let peer_actors = peer_entities
        .into_iter()
        .zip(peer_ports)
        .enumerate()
        .map(|(index, (entities, ports))| {
            PeerActor::new(
                index,
                num_peers,
                sar_ids[index].clone(),
                config.boomerang.clone(),
                config.withdrawal.clone(),
                entities,
                ports,
                peer_directory.clone(),
                peer_registration_barrier.clone(),
                setup_barrier.clone(),
                if index == 0 {
                    Some(InitiatorRuntime {
                        rpc_address: bitcoin_node.params.rpc_socket,
                        cookie_path: bitcoin_node.params.cookie_file.clone(),
                    })
                } else {
                    None
                },
            )
        })
        .collect::<Vec<_>>();

    let mut join_set = JoinSet::new();
    join_set.spawn(async move { wt_actor.run().await });

    for sar_actor in sar_actors {
        join_set.spawn(async move { sar_actor.run().await });
    }

    for peer_actor in peer_actors {
        join_set.spawn(async move { peer_actor.run().await });
    }

    while let Some(join_result) = join_set.join_next().await {
        // Surfacing task panics as errors keeps the legacy runner debuggable without crashing the
        // whole process through an implicit unwrap at the task boundary.
        let task_result = join_result?;
        task_result.map_err(|err| -> Box<dyn std::error::Error> { err })?;
    }

    info!("NetworkedPoC: protocol run finished.");
    Ok(())
}

/// Loads and validates the baked-in legacy concurrent runner config.
///
/// # Why this exists
/// The legacy runner still shares the same protocol assumptions as the supported runtimes, so it
/// should reject invalid defaults before creating actors or talking to bitcoind.
///
/// # Role in the system
/// Used by [`run`] before any actor or Bitcoin node startup occurs.
///
/// # Errors
/// Returns [`ConfigError`] when the default config violates shared topology or protocol bounds.
pub(crate) fn load_config() -> Result<NetworkedPocConfig, ConfigError> {
    let config = NetworkedPocConfig::default();
    config.validate()?;
    Ok(config)
}

/// Validates the topology assumptions that this legacy runner still relies on.
///
/// # Why this exists
/// Unlike the newer standalone runtime, the channel-based prototype allocates one SAR lane per
/// peer and one special initiator peer. Failing fast here prevents silent truncation or index
/// panics later in actor wiring.
///
/// # Role in the system
/// Called by [`run`] immediately after config loading.
///
/// # Errors
/// Returns an [`io::Error`] when the config asks for zero peers or when peers and SARs are not in
/// one-to-one correspondence.
pub(crate) fn validate_topology(
    config: &NetworkedPocConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let num_peers = config.topology.num_peers;
    let num_sars = config.topology.num_sars;

    if num_peers == 0 {
        return Err(io::Error::other(
            "legacy poc-networked requires at least one peer so an initiator can exist",
        )
        .into());
    }

    if num_peers != num_sars {
        return Err(io::Error::other(format!(
            "legacy poc-networked requires matching peer and SAR counts, got {num_peers} peers and {num_sars} SARs"
        ))
        .into());
    }

    Ok(())
}

/// Starts the embedded bitcoind node used by the legacy concurrent proof of concept.
///
/// # Why this exists
/// The legacy runner depends on a local regtest node for protocol steps that touch real Bitcoin
/// RPC surfaces, so startup is centralized here instead of being duplicated across the file.
///
/// # Role in the system
/// Used once by [`run`] before WT and peers are initialized.
///
/// # Errors
/// Returns an [`io::Error`] when bitcoind startup fails.
pub(crate) fn build_bitcoin_node(
    config: &BoomerangNetworkConfig,
) -> Result<Node, Box<dyn std::error::Error>> {
    let mut node_conf = Conf::default();
    node_conf.p2p = P2P::Yes;

    let bitcoin_node =
        Node::with_conf(&config.bitcoind_executable_path, &node_conf).map_err(|error| {
            io::Error::other(format!("failed to start legacy bitcoind node: {error}"))
        })?;
    bitcoin_node.p2p_connect(true);
    Ok(bitcoin_node)
}

/// Creates and initializes the SAR actors used by the legacy concurrent runner.
///
/// # Why this exists
/// The legacy topology assigns one ready SAR identity per peer, so startup needs to return both
/// the actor instances and their registered ids for later peer initialization.
///
/// # Role in the system
/// Used by [`run`] before peer actors are created.
///
/// # Errors
/// Returns an [`io::Error`] if SAR initialization fails or if a started SAR does not expose its
/// identity afterward.
pub(crate) fn build_sars(
    num_sars: usize,
) -> Result<(Vec<Sar>, Vec<SarId>), Box<dyn std::error::Error>> {
    let mut sars = Vec::with_capacity(num_sars);
    let mut sar_ids = Vec::with_capacity(num_sars);

    for index in 0..num_sars {
        let mut sar = Sar::create();
        sar.initialize().map_err(|error| {
            io::Error::other(format!("failed to initialize SAR actor {index}: {error}"))
        })?;
        let sar_id = sar.get_sar_id().ok_or_else(|| {
            io::Error::other(format!("SAR actor {index} did not expose a SAR id"))
        })?;
        sar_ids.push(sar_id);
        sars.push(sar);
    }

    Ok((sars, sar_ids))
}

/// Creates one peer plus its colocated local entities for the legacy concurrent runner.
///
/// # Why this exists
/// The original channel-based prototype still models all peer-local collaborators explicitly, so
/// peer startup is grouped here to keep the main orchestration path readable.
///
/// # Role in the system
/// Used once per peer by [`run`] while constructing the actor graph.
///
/// # Errors
/// Returns an [`io::Error`] when peer initialization fails.
pub(crate) fn build_peer_entities(
    config: &BoomerangNetworkConfig,
    rpc_client_auth: &BitcoinCoreAuth,
    rpc_client_url: std::net::SocketAddrV4,
    wt_ids_collection: WtIdsCollection,
    sar_id: SarId,
) -> Result<PeerEntities, Box<dyn std::error::Error>> {
    let mut peer = Peer::create();
    peer.initialize(
        config.milestone_block_0,
        config.milestone_block_1,
        config.milestone_block_2,
        config.milestone_block_3,
        config.milestone_block_4,
        config.milestone_block_5,
        config.network,
        rpc_client_url,
        rpc_client_auth.clone(),
        wt_ids_collection,
        BTreeSet::from([sar_id]),
    )
    .map_err(|error| io::Error::other(format!("failed to initialize peer entity: {error}")))?;

    Ok(PeerEntities {
        peer,
        iso: Iso::create(),
        niso: Niso::create_with_params(NisoCreateParams::new(
            config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
            config.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
            config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            config.required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
            config.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
            config.tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
            config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
            config.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
            config.required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers,
        )),
        boomlet: build_boomlet(config),
        boomletwo: build_boomlet(config),
        phone: Phone::create(),
        st: St::create(),
    })
}

/// Builds one boomlet instance with the shared legacy POC timing configuration.
///
/// # Why this exists
/// Each peer uses two boomlet-style collaborators in the legacy topology, and centralizing the
/// shared constructor parameters prevents them from drifting apart.
pub(crate) fn build_boomlet(config: &BoomerangNetworkConfig) -> Boomlet {
    Boomlet::create(
        config.duress_check_interval_in_blocks,
        config.min_tries_for_digging_game_in_blocks,
        config.max_tries_for_digging_game_in_blocks,
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        config.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_wt_tx_approval_by_non_initiator_peers,
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config.required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_initiator_peer_tx_commitment_by_non_initiator_peers,
        config.tolerance_in_blocks_from_tx_commitment_by_initiator_and_non_initiator_peers_to_receiving_tx_commitment_by_all_peers,
        config.tolerance_in_blocks_from_creating_pong_by_wt_to_reviewing_the_pong_in_peers_boomlet,
        config.tolerance_in_blocks_from_creating_ping_by_other_peers_to_reviewing_the_ping_in_peer_boomlet,
        config.jump_in_blocks_if_last_seen_block_lags_behind_niso_event_block_height_in_boomlet,
        config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_initiator_peer,
        config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peers_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        config.tolerance_in_blocks_from_tx_approval_by_wt_to_receiving_non_initiator_tx_approval_by_other_non_initiator_peers,
        config.required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers,
    )
}

/// Creates and initializes the WT used by the legacy concurrent runner.
///
/// # Why this exists
/// WT startup depends on both the legacy POC timing parameters and the freshly started Bitcoin RPC
/// endpoint, so it lives in one helper instead of being spread across the main orchestration path.
///
/// # Role in the system
/// Used once by [`run`] before actor construction.
///
/// # Errors
/// Returns an [`io::Error`] when WT initialization fails.
pub(crate) fn build_wt(
    config: &BoomerangNetworkConfig,
    rpc_client_auth: &BitcoinCoreAuth,
    rpc_client_url: std::net::SocketAddrV4,
) -> Result<Wt, Box<dyn std::error::Error>> {
    let mut wt = Wt::create_with_params(WtCreateParams::new(
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
        config.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
        config.tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
        config.tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
        config.wt_sleeping_time_to_check_for_new_block_in_milliseconds,
        config.required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config.required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers,
        config.required_minimum_distance_in_blocks_between_ping_and_pong,
    ));
    wt.initialize(rpc_client_url.to_string(), rpc_client_auth.clone())
        .map_err(|error| io::Error::other(format!("failed to initialize WT: {error}")))?;
    Ok(wt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirms the baked-in legacy concurrent config still validates.
    #[test]
    fn default_startup_config_is_valid() {
        assert!(load_config().is_ok());
    }

    /// Guards the legacy assumption that each peer gets one SAR lane.
    #[test]
    fn topology_requires_matching_peer_and_sar_counts() {
        let mut config = NetworkedPocConfig::default();
        config.topology.num_sars += 1;
        assert!(validate_topology(&config).is_err());
    }
}
