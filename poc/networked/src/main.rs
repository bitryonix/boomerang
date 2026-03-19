mod actors;
mod config;
mod envelopes;
mod local_actor;
mod transport;

use std::collections::{BTreeMap, BTreeSet};

use actors::{
    peer_actor::{InitiatorRuntime, PeerActor, PeerEntities, PeerPorts},
    sar_actor::SarActor,
    wt_actor::WtActor,
};
use boomlet::Boomlet;
use config::{BoomerangNetworkConfig, NetworkedPocConfig};
use corepc_node::{Conf, Node, P2P};
use iso::Iso;
use niso::Niso;
use peer::Peer;
use phone::Phone;
use protocol::constructs::{BitcoinCoreAuth, WtIdsCollection};
use sar::Sar;
use st::St;
use tokio::sync::Barrier;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use transport::channel;
use wt::Wt;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing()?;

    let config = NetworkedPocConfig::default();
    let num_peers = config.topology.num_peers;
    let num_sars = config.topology.num_sars;
    let channel_capacity = config.topology.channel_capacity;

    assert_eq!(num_peers, 5, "networked-poc runs exactly 5 peers");
    assert_eq!(num_sars, 5, "networked-poc runs exactly 5 SARs");

    info!(
        "NetworkedPoC: booting {num_peers} peers, {num_sars} SARs, and 1 WT with Tokio-channel transport (capacity {channel_capacity})."
    );

    let mut node_conf = Conf::default();
    node_conf.p2p = P2P::Yes;
    let bitcoin_node =
        Node::with_conf(&config.boomerang.bitcoind_executable_path, &node_conf).unwrap();
    bitcoin_node.p2p_connect(true);
    let rpc_client_url = bitcoin_node.params.rpc_socket;
    let rpc_client_auth = BitcoinCoreAuth::CookieFile(bitcoin_node.params.cookie_file.clone());

    let mut sars = Vec::with_capacity(num_sars);
    let mut sar_ids = Vec::with_capacity(num_sars);
    for _ in 0..num_sars {
        let mut sar = Sar::create();
        sar.initialize().unwrap();
        sar_ids.push(sar.get_sar_id().unwrap());
        sars.push(sar);
    }

    let wt = build_wt(&config.boomerang, &rpc_client_auth, rpc_client_url);
    let wt_ids_collection = WtIdsCollection::new(wt.get_wt_id().unwrap(), BTreeSet::new());

    let peer_directory = transport::PeerDirectory::new();
    let peer_registration_barrier = std::sync::Arc::new(Barrier::new(num_peers));
    let setup_barrier = std::sync::Arc::new(Barrier::new(num_peers + num_sars + 1));

    let mut peer_entities = Vec::with_capacity(num_peers);
    for sar_id in sar_ids.iter().take(num_peers) {
        peer_entities.push(build_peer_entities(
            &config.boomerang,
            &rpc_client_auth,
            rpc_client_url,
            wt_ids_collection.clone(),
            sar_id.clone(),
        ));
    }

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

    let mut sar_actors = Vec::with_capacity(num_sars);
    for (sar, (peer_to_sar_rx, sar_to_peer_tx, wt_to_sar_rx, sar_to_wt_tx)) in
        sars.into_iter().zip(sar_ports.into_iter())
    {
        sar_actors.push(SarActor::new(
            sar,
            peer_to_sar_rx,
            sar_to_peer_tx,
            wt_to_sar_rx,
            sar_to_wt_tx,
            setup_barrier.clone(),
        ));
    }

    let mut peer_actors = Vec::with_capacity(num_peers);
    for (index, (entities, ports)) in peer_entities
        .into_iter()
        .zip(peer_ports.into_iter())
        .enumerate()
    {
        peer_actors.push(PeerActor::new(
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
        ));
    }

    let mut sar_actors = sar_actors.into_iter();
    let sar_actor_1 = sar_actors.next().expect("missing SAR actor 1");
    let sar_actor_2 = sar_actors.next().expect("missing SAR actor 2");
    let sar_actor_3 = sar_actors.next().expect("missing SAR actor 3");
    let sar_actor_4 = sar_actors.next().expect("missing SAR actor 4");
    let sar_actor_5 = sar_actors.next().expect("missing SAR actor 5");
    assert!(sar_actors.next().is_none(), "unexpected extra SAR actors");

    let mut peer_actors = peer_actors.into_iter();
    let peer_actor_1 = peer_actors.next().expect("missing peer actor 1");
    let peer_actor_2 = peer_actors.next().expect("missing peer actor 2");
    let peer_actor_3 = peer_actors.next().expect("missing peer actor 3");
    let peer_actor_4 = peer_actors.next().expect("missing peer actor 4");
    let peer_actor_5 = peer_actors.next().expect("missing peer actor 5");
    assert!(peer_actors.next().is_none(), "unexpected extra peer actors");

    tokio::join!(
        wt_actor.run(),
        sar_actor_1.run(),
        sar_actor_2.run(),
        sar_actor_3.run(),
        sar_actor_4.run(),
        sar_actor_5.run(),
        peer_actor_1.run(),
        peer_actor_2.run(),
        peer_actor_3.run(),
        peer_actor_4.run(),
        peer_actor_5.run(),
    );

    info!("NetworkedPoC: protocol run finished.");

    Ok(())
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into());
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .pretty()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

fn build_peer_entities(
    config: &BoomerangNetworkConfig,
    rpc_client_auth: &BitcoinCoreAuth,
    rpc_client_url: std::net::SocketAddrV4,
    wt_ids_collection: WtIdsCollection,
    sar_id: protocol::constructs::SarId,
) -> PeerEntities {
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
    .unwrap();

    PeerEntities {
        peer,
        iso: Iso::create(),
        niso: Niso::create(
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
        ),
        boomlet: build_boomlet(config),
        boomletwo: build_boomlet(config),
        phone: Phone::create(),
        st: St::create(),
    }
}

fn build_boomlet(config: &BoomerangNetworkConfig) -> Boomlet {
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

fn build_wt(
    config: &BoomerangNetworkConfig,
    rpc_client_auth: &BitcoinCoreAuth,
    rpc_client_url: std::net::SocketAddrV4,
) -> Wt {
    let mut wt = Wt::create(
        config.tolerance_in_blocks_from_tx_approval_by_initiator_peer_to_tx_approval_by_wt,
        config.tolerance_in_blocks_from_tx_approval_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_approval_by_wt,
        config.tolerance_in_blocks_from_tx_commitment_by_initiator_peer_to_receiving_sar_response_by_wt,
        config.tolerance_in_blocks_from_creating_ping_to_receiving_all_pings_by_wt_and_having_sar_response_back_to_wt,
        config.tolerance_in_blocks_from_tx_commitment_by_non_initiator_peer_to_receiving_non_initiator_peers_tx_commitment_by_wt_having_sar_response_back_to_wt,
        config.wt_sleeping_time_to_check_for_new_block_in_milliseconds,
        config.required_minimum_distance_in_blocks_between_initiator_peer_tx_approval_and_receiving_all_non_initiator_tx_approvals_by_initiator_peer,
        config.required_minimum_distance_in_blocks_between_peer_tx_commitment_and_receiving_all_tx_commitment_by_peers,
        config.required_minimum_distance_in_blocks_between_ping_and_pong,
    );
    wt.initialize(rpc_client_url.to_string(), rpc_client_auth.clone())
        .unwrap();
    wt
}
